#include "nat_traversal.h"

#include "config_manager.h"
#include "logger.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#if defined(__linux__)
#include <limits.h>
#endif

namespace {

inline bool is_single_thread_mode() {
	static const bool enabled = []() {
#if defined(LITEP2P_SINGLE_THREAD_MODE_COMPILE) && LITEP2P_SINGLE_THREAD_MODE_COMPILE
		return true;  // Compile-time enabled
#else
		const char* v = std::getenv("LITEP2P_SINGLE_THREAD_MODE");
		if (!v) return false;
		return std::string(v) != "0";
#endif
	}();
	return enabled;
}

int64_t systemNowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch()).count();
}

bool fileReadable(const std::string& path) {
	return !path.empty() && ::access(path.c_str(), R_OK) == 0;
}

std::string getExecutablePath() {
#if defined(__APPLE__)
	uint32_t size = 0;
	if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) {
		// size now contains required buffer length
	}
	std::string buffer(size, '\0');
	if (_NSGetExecutablePath(buffer.data(), &size) == 0) {
		buffer.resize(std::strlen(buffer.c_str()));
		return buffer;
	}
	return {};
#elif defined(__linux__)
	char buf[PATH_MAX];
	ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (len > 0) {
		buf[len] = '\0';
		return std::string(buf);
	}
	return {};
#else
	return {};
#endif
}

std::string getExecutableDir() {
	std::string exe = getExecutablePath();
	if (exe.empty()) {
		return {};
	}
	try {
		return std::filesystem::path(exe).parent_path().string();
	} catch (...) {
		return {};
	}
}

std::string joinPath(const std::string& dir, const std::string& leaf) {
	if (dir.empty()) return leaf;
	try {
		return (std::filesystem::path(dir) / leaf).string();
	} catch (...) {
		return dir + "/" + leaf;
	}
}

std::string findConfigUpwards(const std::string& start_dir, const std::string& filename, int max_levels) {
	if (start_dir.empty() || max_levels <= 0) {
		return {};
	}

	try {
		std::filesystem::path current(start_dir);
		for (int i = 0; i <= max_levels; ++i) {
			std::string candidate = (current / filename).string();
			if (fileReadable(candidate)) {
				return candidate;
			}
			if (!current.has_parent_path()) {
				break;
			}
			auto parent = current.parent_path();
			if (parent == current) {
				break;
			}
			current = parent;
		}
	} catch (...) {
		return {};
	}

	return {};
}

std::string serverToString(const STUNServer& server) {
	std::ostringstream oss;
	oss << server.hostname << ":" << server.port << "/" << server.protocol;
	return oss.str();
}

std::vector<uint8_t> makeHeartbeatPayload() {
	STUNMessage heartbeat;
	heartbeat.setType(STUNMessageType::BindingIndication);
	return heartbeat.encode();
}

bool resolveIpv4(const std::string& hostname, uint16_t port, std::string& out_ip) {
	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	struct addrinfo* result = nullptr;
	const int err = ::getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hints, &result);
	if (err != 0 || result == nullptr) {
		return false;
	}

	char buf[INET_ADDRSTRLEN];
	const auto* addr4 = reinterpret_cast<const struct sockaddr_in*>(result->ai_addr);
	const char* ok = ::inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf));
	::freeaddrinfo(result);
	if (!ok) {
		return false;
	}
	out_ip.assign(buf);
	return true;
}

} // namespace

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

std::string NATTraversal::transactionKey(const std::vector<uint8_t>& tx_id) {
	return std::string(tx_id.begin(), tx_id.end());
}

// -----------------------------------------------------------------------------
// Singleton lifecycle
// -----------------------------------------------------------------------------

NATTraversal& NATTraversal::getInstance() {
	static NATTraversal instance;
	return instance;
}

NATTraversal::NATTraversal() = default;

NATTraversal::~NATTraversal() {
	shutdown();
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

bool NATTraversal::initialize(uint16_t local_port) {
	if (initialized_.load()) {
		nativeLog("NAT: initialize called more than once; ignoring");
		return true;
	}

	shutdown_requested_ = false;
	stun_client_.clearCancel();
	local_port_ = local_port;

	// Reset punch state so a previous shutdown (which sets punch_shutdown_=true)
	// doesn't prevent hole punching after re-initialization in single-thread mode.
	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		punch_shutdown_ = false;
		std::queue<PeerAddress> empty;
		std::swap(punch_queue_, empty);
		punch_queued_peers_.clear();
		punch_inflight_peers_.clear();
		punch_reschedule_latest_.clear();
		punch_cancelled_peers_.clear();
		punch_last_failure_ms_.clear();
	}

	ensureConfigurationLoaded();

	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		loadOptionsLocked();
	}

	{
		std::lock_guard<std::mutex> lock(stun_mutex_);
		refreshStunServerListLocked();
	}

	heartbeat_payload_ = makeHeartbeatPayload();

	// In single-thread mode, skip background threads (NAT detection is done synchronously)
	// Use on-demand punch mode instead of permanent thread pool
	if (!is_single_thread_mode()) {
		startHeartbeatThread();
		startMaintenanceThread();
		// Use on-demand punch threads instead of permanent pool
		on_demand_punch_mode_ = true;
		nativeLog("NAT: Using on-demand punch threads (max " + std::to_string(MAX_ON_DEMAND_PUNCH_THREADS) + ")");
	} else {
		on_demand_punch_mode_ = true;  // Single-thread mode also uses on-demand
		nativeLog("NAT: Single-thread mode - skipping background threads, on-demand punch enabled");
	}

	initialized_ = true;

	nativeLog("NAT: Initialized on local port " + std::to_string(local_port_));
	return true;
}

void NATTraversal::shutdown() {
	if (!initialized_.load()) {
		return;
	}

	shutdown_requested_ = true;
	stun_client_.requestCancel();

	{
		std::lock_guard<std::mutex> lock(heartbeat_mutex_);
		heartbeat_stop_requested_ = true;
	}
	{
		std::lock_guard<std::mutex> lock(maintenance_mutex_);
		maintenance_stop_requested_ = true;
	}

	punch_cv_.notify_all();
	heartbeat_cv_.notify_all();
	maintenance_cv_.notify_all();
	{
		std::lock_guard<std::mutex> lock(pending_mutex_);
		pending_transactions_.clear();
	}
	pending_cv_.notify_all();

	stopHeartbeatThread();
	stopMaintenanceThread();
	stopPunchThreadPool();
	clearPunchQueue();
	
	// Wait for any on-demand punch threads to complete
	if (on_demand_punch_mode_) {
		int wait_count = 0;
		while (active_on_demand_punches_.load() > 0 && wait_count < 50) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			wait_count++;
		}
		if (active_on_demand_punches_.load() > 0) {
			nativeLog("NAT: Warning - " + std::to_string(active_on_demand_punches_.load()) + " on-demand punch threads still active at shutdown");
		}
	}

	if (engine_thread_.joinable()) {
		engine_thread_.join();
	}

	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		peers_by_id_.clear();
	}

	{
		std::lock_guard<std::mutex> lock(mapping_mutex_);
		mappings_by_id_.clear();
	}

	if (auto* manager = connection_manager_.exchange(nullptr)) {
		manager->setStunPacketCallback({});
	}

	initialized_ = false;
	nativeLog("NAT: Shutdown complete");
}

void NATTraversal::requestCancel() {
	shutdown_requested_ = true;
	stun_client_.requestCancel();
	pending_cv_.notify_all();
	heartbeat_cv_.notify_all();
	maintenance_cv_.notify_all();
	punch_cv_.notify_all();
}

void NATTraversal::startEngineStaged(uint16_t local_port) {
	if (engine_thread_.joinable()) {
		nativeLog("NAT: Engine thread already running");
		return;
	}

	engine_thread_ = std::thread([this, local_port]() {
		try {
			nativeLog("NAT: Engine thread bootstrapping");
			initialize(local_port);

			sendDiscoveryPackets();
			updateLocalPeersFromDiscovery();

			NATInfo info = detectNATType();
			nativeLog("NAT: Initial NAT detection completed - " + natTypeToString(info.nat_type));

			sendNetworkBroadcast();
		} catch (const std::exception& e) {
			nativeLog(std::string("NAT: Engine thread terminated by exception: ") + e.what());
		} catch (...) {
			nativeLog("NAT: Engine thread terminated by unknown exception");
		}
	});
}

// -----------------------------------------------------------------------------
// Configuration loading
// -----------------------------------------------------------------------------

void NATTraversal::ensureConfigurationLoaded() {
	ConfigManager& cfg = ConfigManager::getInstance();
	if (!cfg.getConfigSnapshot().is_null()) {
		return;
	}

	std::string existing_path = cfg.getConfigPath();
	if (!existing_path.empty() && fileReadable(existing_path) && cfg.loadConfig(existing_path)) {
		return;
	}

	if (const char* env_path = std::getenv("LITEP2P_CONFIG_PATH")) {
		std::string env(env_path);
		if (fileReadable(env) && cfg.loadConfig(env)) {
			return;
		}
	}

	// Prefer config.json near the executable (desktop builds), then walk up towards repo root.
	const std::string exe_dir = getExecutableDir();
	if (!exe_dir.empty()) {
		std::string near_exe = joinPath(exe_dir, "config.json");
		if (fileReadable(near_exe) && cfg.loadConfig(near_exe)) {
			return;
		}
		std::string upward = findConfigUpwards(exe_dir, "config.json", 10);
		if (!upward.empty() && cfg.loadConfig(upward)) {
			return;
		}
	}

	// Fall back to current working directory only if the file exists.
	if (fileReadable("config.json") && cfg.loadConfig("config.json")) {
		return;
	}

	// No configuration found; proceed with ConfigManager defaults.
	static std::atomic_bool warned{false};
	if (!warned.exchange(true)) {
		LOG_INFO("NAT: No config file found; using built-in defaults (set LITEP2P_CONFIG_PATH to override)");
	}
}

void NATTraversal::reloadConfiguration() {
	ensureConfigurationLoaded();

	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		loadOptionsLocked();
	}

	{
		std::lock_guard<std::mutex> lock(stun_mutex_);
		refreshStunServerListLocked();
	}

	reconcilePunchThreadPoolSize();
	heartbeat_cv_.notify_all();
	maintenance_cv_.notify_all();
}

void NATTraversal::loadOptionsLocked() {
	ConfigManager& cfg = ConfigManager::getInstance();
	Options loaded;
	loaded.stun_enabled = cfg.isSTUNEnabled();
	loaded.upnp_enabled = cfg.isUPnPEnabled();
	loaded.hole_punching_enabled = cfg.isHolePunchingEnabled();
	loaded.stun_timeout_ms = cfg.getStunTimeout();
	loaded.heartbeat_interval_sec = cfg.getNATHeartbeatIntervalSec();
	loaded.heartbeat_timeout_ms = cfg.getNATHeartbeatTimeoutMs();
	loaded.cleanup_interval_sec = cfg.getNATCleanupIntervalSec();
	loaded.hole_punch_max_attempts = cfg.getMaxExternalPortAttempts();

	json snapshot = cfg.getConfigSnapshot();
	if (!snapshot.is_null() && snapshot.contains("nat_traversal")) {
		const auto& nat = snapshot["nat_traversal"];
		loaded.hole_punch_max_attempts = nat.value("hole_punch_max_attempts", loaded.hole_punch_max_attempts);
		loaded.hole_punch_initial_backoff_ms = nat.value("hole_punch_retry_backoff_ms", loaded.hole_punch_initial_backoff_ms);
		loaded.punch_thread_pool_size = nat.value("hole_punch_thread_pool_size", loaded.punch_thread_pool_size);
		loaded.punch_queue_limit = nat.value("hole_punch_queue_limit", loaded.punch_queue_limit);
		loaded.upnp_lease_duration_sec = nat.value("upnp_lease_duration_sec", loaded.upnp_lease_duration_sec);
		loaded.max_missed_heartbeats = nat.value("max_missed_heartbeats", loaded.max_missed_heartbeats);
	}

	loaded.punch_thread_pool_size = std::max(1, loaded.punch_thread_pool_size);
	loaded.hole_punch_initial_backoff_ms = std::max(50, loaded.hole_punch_initial_backoff_ms);
	loaded.punch_queue_limit = std::clamp(loaded.punch_queue_limit, 1, 2048);
	loaded.hole_punch_max_attempts = std::max(1, loaded.hole_punch_max_attempts);
	loaded.max_missed_heartbeats = std::max(1, loaded.max_missed_heartbeats);
	loaded.upnp_lease_duration_sec = std::max(0, loaded.upnp_lease_duration_sec);
	options_ = loaded;
}

void NATTraversal::refreshStunServerListLocked() {
	ConfigManager& cfg = ConfigManager::getInstance();
	std::vector<STUNServer> servers;

	json snapshot = cfg.getConfigSnapshot();
	if (!snapshot.is_null() && snapshot.contains("nat_traversal")) {
		auto& nat = snapshot["nat_traversal"];
		if (nat.contains("stun_servers")) {
			for (const auto& entry : nat["stun_servers"]) {
				STUNServer s;
				s.hostname = entry.value("hostname", "");
				s.port = entry.value("port", 3478);
				s.protocol = entry.value("protocol", "UDP");
				if (!s.hostname.empty()) {
					servers.push_back(s);
				}
			}
		}
	}

	if (servers.empty()) {
		servers.push_back({"stun.l.google.com", 19302, "UDP"});
		servers.push_back({"stun1.l.google.com", 19302, "UDP"});
		servers.push_back({"stun.voip.blackberry.com", 3478, "UDP"});
		servers.push_back({"stun.stunprotocol.org", 3478, "UDP"});
	}

	stun_servers_ = std::move(servers);
}

void NATTraversal::reconcilePunchThreadPoolSize() {
	int desired = 0;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		desired = std::max(1, options_.punch_thread_pool_size);
	}

	if (desired == current_punch_worker_count_) {
		return;
	}

	stopPunchThreadPool();
	startPunchThreadPool();
}

// -----------------------------------------------------------------------------
// Connection manager integration
// -----------------------------------------------------------------------------

void NATTraversal::setConnectionManager(IUdpConnectionManager* manager) {
	IUdpConnectionManager* previous = nullptr;
	{
		std::lock_guard<std::mutex> lock(connection_mutex_);
		previous = connection_manager_.exchange(manager);
	}

	if (previous && previous != manager) {
		previous->setStunPacketCallback({});
	}

	if (manager) {
		manager->setStunPacketCallback([this](const std::string& ip, int port, const std::vector<uint8_t>& data) {
			handleStunPacket(ip, port, data);
		});
		nativeLog("NAT: Connection manager registered");
	}
}

void NATTraversal::setUpnpController(std::shared_ptr<IUpnpController> controller) {
	std::lock_guard<std::mutex> lock(upnp_mutex_);
	upnp_controller_ = std::move(controller);
}

// -----------------------------------------------------------------------------
// Peer management
// -----------------------------------------------------------------------------

void NATTraversal::registerPeer(const PeerAddress& peer) {
	size_t peer_count = 0;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);

		PeerAddress copy = peer;
		copy.last_heartbeat_ms = systemNowMs();
		copy.missed_heartbeats = 0;

		peers_by_id_[copy.peer_id] = copy;
		peer_count = peers_by_id_.size();
		nativeLog("NAT: Registered peer " + copy.peer_id + " (network=" + copy.network_id + ")");
	}

	// A fresh registration implies we want to allow punching again.
	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		punch_cancelled_peers_.erase(peer.peer_id);
		punch_last_failure_ms_.erase(peer.peer_id);
		punch_reschedule_latest_.erase(peer.peer_id);
	}

	// Update peer count metric
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.active_peers = static_cast<int>(peer_count);
	}
}

void NATTraversal::cancelHolePunching(const std::string& peer_id) {
	if (peer_id.empty()) {
		return;
	}

	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		punch_cancelled_peers_.insert(peer_id);
		punch_reschedule_latest_.erase(peer_id);
		punch_last_failure_ms_.erase(peer_id);
		punch_queued_peers_.erase(peer_id);

		// Remove any queued tasks for this peer.
		if (!punch_queue_.empty()) {
			std::queue<PeerAddress> filtered;
			while (!punch_queue_.empty()) {
				PeerAddress p = punch_queue_.front();
				punch_queue_.pop();
				if (p.peer_id != peer_id) {
					filtered.push(std::move(p));
				}
			}
			punch_queue_ = std::move(filtered);
		}
	}

	// Wake up any in-flight waiters quickly.
	punch_cv_.notify_all();
	pending_cv_.notify_all();
}

void NATTraversal::unregisterPeer(const std::string& peer_id) {
	if (peer_id.empty()) {
		return;
	}

	// Cancel any queued/in-flight punch work first.
	cancelHolePunching(peer_id);

	size_t peer_count = 0;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		peers_by_id_.erase(peer_id);
		peer_count = peers_by_id_.size();
	}

	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.active_peers = static_cast<int>(peer_count);
	}
}

std::vector<PeerAddress> NATTraversal::getRegisteredPeers() const {
	std::lock_guard<std::mutex> lock(peers_mutex_);
	std::vector<PeerAddress> peers;
	peers.reserve(peers_by_id_.size());
	for (const auto& [_, peer] : peers_by_id_) {
		peers.push_back(peer);
	}
	return peers;
}

std::vector<PeerAddress> NATTraversal::getNetworkPeers(const std::string& network_id) const {
	std::vector<PeerAddress> filtered;
	std::lock_guard<std::mutex> lock(peers_mutex_);
	for (const auto& [_, peer] : peers_by_id_) {
		if (peer.network_id == network_id) {
			filtered.push_back(peer);
		}
	}
	nativeLog("NAT: Found " + std::to_string(filtered.size()) + " peers for network " + network_id);
	return filtered;
}

bool NATTraversal::performHolePunching(const std::string& peer_id) {
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto it = peers_by_id_.find(peer_id);
	if (it == peers_by_id_.end()) {
		nativeLog("NAT: performHolePunching - peer not found: " + peer_id);
		return false;
	}
	enqueuePunchTask(it->second);
	return true;
}

bool NATTraversal::performNetworkHolePunching(const std::string& peer_id, const std::string& network_id) {
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto it = peers_by_id_.find(peer_id);
	if (it == peers_by_id_.end() || it->second.network_id != network_id) {
		nativeLog("NAT: performNetworkHolePunching - peer/network mismatch for " + peer_id);
		return false;
	}
	enqueuePunchTask(it->second);
	return true;
}

void NATTraversal::enqueuePunchTask(const PeerAddress& peer) {
	Options options_snapshot;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		options_snapshot = options_;
	}

	if (!options_snapshot.hole_punching_enabled) {
		nativeLog("NAT: Hole punching disabled by configuration");
		return;
	}

	if (shutdown_requested_.load()) {
		nativeLog("NAT: Ignoring punch task; shutdown in progress");
		return;
	}

	if (!connection_manager_.load()) {
		nativeLog("NAT: Cannot schedule punch task without connection manager");
		return;
	}

	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		if (punch_shutdown_) {
			nativeLog("NAT: Punch shutdown; dropping task for " + peer.peer_id);
			return;
		}

		if (punch_cancelled_peers_.find(peer.peer_id) != punch_cancelled_peers_.end()) {
			nativeLog("NAT: Punch cancelled for peer " + peer.peer_id + "; dropping task");
			return;
		}

		const int cooldown_ms = std::max(0, options_snapshot.hole_punch_failure_cooldown_ms);
		if (cooldown_ms > 0) {
			const int64_t now_ms = systemNowMs();
			auto fail_it = punch_last_failure_ms_.find(peer.peer_id);
			if (fail_it != punch_last_failure_ms_.end()) {
				const int64_t delta = now_ms - fail_it->second;
				if (delta >= 0 && delta < cooldown_ms) {
					nativeLog("NAT: Punch cooldown active for peer " + peer.peer_id + " (" + std::to_string(delta) + "ms since failure); skipping");
					return;
				}
			}
		}
		// Coalesce repeated scheduling attempts for the same peer.
		if (punch_inflight_peers_.find(peer.peer_id) != punch_inflight_peers_.end()) {
			punch_reschedule_latest_[peer.peer_id] = peer;
			nativeLog("NAT: Punch already in progress for peer " + peer.peer_id + "; coalescing reschedule");
			return;
		}
		
		// On-demand mode: spawn a temporary thread for this punch
		if (on_demand_punch_mode_) {
			// Check if we're at max concurrent punches
			if (active_on_demand_punches_.load() >= MAX_ON_DEMAND_PUNCH_THREADS) {
				nativeLog("NAT: Max on-demand punch threads reached; dropping task for " + peer.peer_id);
				return;
			}
			
			punch_inflight_peers_.insert(peer.peer_id);
			active_on_demand_punches_++;
			
			// Spawn detached thread that will self-terminate after punch completes
			std::thread([this, peer]() {
				try {
					nativeLog("NAT: On-demand punch thread started for " + peer.peer_id);
					
					(void)performHolePunchingInternal(peer);
				} catch (const std::exception& e) {
					nativeLog(std::string("NAT: On-demand punch thread exception for ") + peer.peer_id + ": " + e.what());
				} catch (...) {
					nativeLog("NAT: On-demand punch thread unknown exception for " + peer.peer_id);
				}
				
				// Handle reschedule if needed
				PeerAddress reschedule_peer;
				bool should_reschedule = false;
				{
					std::lock_guard<std::mutex> lock(punch_mutex_);
					punch_inflight_peers_.erase(peer.peer_id);
					auto it = punch_reschedule_latest_.find(peer.peer_id);
					if (it != punch_reschedule_latest_.end()) {
						reschedule_peer = it->second;
						punch_reschedule_latest_.erase(it);
						should_reschedule = !punch_shutdown_ && !shutdown_requested_.load();
					}
				}
				
				active_on_demand_punches_--;
				nativeLog("NAT: On-demand punch thread finished for " + peer.peer_id);
				
				if (should_reschedule) {
					enqueuePunchTask(reschedule_peer);
				}
			}).detach();
			
			nativeLog("NAT: Spawned on-demand punch thread for peer " + peer.peer_id);
			return;
		}
		
		// Legacy thread pool mode
		if (punch_queued_peers_.find(peer.peer_id) != punch_queued_peers_.end()) {
			punch_reschedule_latest_[peer.peer_id] = peer;
			nativeLog("NAT: Punch already queued for peer " + peer.peer_id + "; coalescing endpoint update");
			return;
		}
		if (static_cast<int>(punch_queue_.size()) >= options_snapshot.punch_queue_limit) {
			nativeLog("NAT: Punch queue saturated; dropping task for " + peer.peer_id);
			return;
		}
		punch_queue_.push(peer);
		punch_queued_peers_.insert(peer.peer_id);
	}

	punch_cv_.notify_one();
	nativeLog("NAT: Scheduled hole punch task for peer " + peer.peer_id);
}

void NATTraversal::punchWorkerLoop() {
	while (true) {
		PeerAddress peer;
		{
			std::unique_lock<std::mutex> lock(punch_mutex_);
			punch_cv_.wait(lock, [this]() {
				return punch_shutdown_ || shutdown_requested_.load() || !punch_queue_.empty();
			});

			if ((punch_shutdown_ || shutdown_requested_.load()) && punch_queue_.empty()) {
				return;
			}

			peer = punch_queue_.front();
			punch_queue_.pop();
			punch_queued_peers_.erase(peer.peer_id);
			punch_inflight_peers_.insert(peer.peer_id);
		}

		try {
			(void)performHolePunchingInternal(peer);
		} catch (const std::exception& e) {
			nativeLog(std::string("NAT: Punch worker exception for ") + peer.peer_id + ": " + e.what());
		} catch (...) {
			nativeLog("NAT: Punch worker unknown exception for " + peer.peer_id);
		}

		// Allow a coalesced reschedule (at most one) after this run completes.
		PeerAddress reschedule_peer;
		bool should_reschedule = false;
		{
			std::lock_guard<std::mutex> lock(punch_mutex_);
			punch_inflight_peers_.erase(peer.peer_id);
			auto it = punch_reschedule_latest_.find(peer.peer_id);
			if (it != punch_reschedule_latest_.end()) {
				reschedule_peer = it->second;
				punch_reschedule_latest_.erase(it);
				// Only reschedule if still allowed and the pool is active.
				should_reschedule = !punch_shutdown_ && !shutdown_requested_.load();
			}
		}

		if (should_reschedule) {
			enqueuePunchTask(reschedule_peer);
		}
	}
}

bool NATTraversal::performHolePunchingInternal(const PeerAddress& peer) {
	if (shutdown_requested_.load()) {
		return false;
	}

	auto is_cancelled = [this, &peer]() -> bool {
		std::lock_guard<std::mutex> lock(punch_mutex_);
		return punch_cancelled_peers_.find(peer.peer_id) != punch_cancelled_peers_.end();
	};

	if (is_cancelled()) {
		return false;
	}

	// Track hole punch attempt
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.hole_punch_attempts++;
	}

	Options options_copy;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		options_copy = options_;
	}

	const int max_attempts = std::max(1, options_copy.hole_punch_max_attempts);
	int backoff_ms = std::max(100, options_copy.hole_punch_initial_backoff_ms);

	for (int attempt = 1; attempt <= max_attempts; ++attempt) {
		if (shutdown_requested_.load()) {
			return false;
		}
		if (is_cancelled()) {
			return false;
		}

		IUdpConnectionManager* manager = connection_manager_.load();
		if (!manager) {
			nativeLog("NAT: performHolePunchingInternal - connection manager unavailable");
			return false;
		}

		STUNMessage request;
		request.setType(STUNMessageType::BindingRequest);
		std::vector<uint8_t> payload = request.encode();
		std::string key = transactionKey(request.getTransactionId());

		{
			std::lock_guard<std::mutex> lock(pending_mutex_);
			pending_transactions_[key] = PendingTransaction();
		}

		nativeLog("NAT: Hole punch attempt " + std::to_string(attempt) + "/" + std::to_string(max_attempts) + " to " + peer.peer_id);
		manager->sendRawPacket(peer.external_ip, peer.external_port, payload);

		bool success = false;
		{
			std::unique_lock<std::mutex> lock(pending_mutex_);
			if (pending_cv_.wait_for(lock, std::chrono::milliseconds(backoff_ms), [&]() {
				if (shutdown_requested_.load()) {
					return true;
				}
				if (is_cancelled()) {
					return true;
				}
				auto it = pending_transactions_.find(key);
				return it != pending_transactions_.end() && it->second.completed;
			})) {
				if (!shutdown_requested_.load() && !is_cancelled()) {
					success = true;
				}
				pending_transactions_.erase(key);
			} else {
				pending_transactions_.erase(key);
			}
		}

		if (success) {
			nativeLog("NAT: Hole punching succeeded for peer " + peer.peer_id);
			markPeerPunchSuccess(peer.peer_id);
			// Track successful hole punch
			{
				std::lock_guard<std::mutex> lock(metrics_mutex_);
				metrics_.hole_punch_successes++;
			}
			return true;
		}

		backoff_ms = std::min(backoff_ms * 2, 4000);
	}

	// If the job was cancelled mid-flight, exit quietly.
	if (is_cancelled() || shutdown_requested_.load()) {
		return false;
	}

	nativeLog("NAT: Hole punching exhausted retries for peer " + peer.peer_id);
	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		punch_last_failure_ms_[peer.peer_id] = systemNowMs();
	}
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.hole_punch_failures++;
	}
	return false;
}

void NATTraversal::markPeerPunchSuccess(const std::string& peer_id) {
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto it = peers_by_id_.find(peer_id);
	if (it != peers_by_id_.end()) {
		it->second.last_successful_punch_ms = systemNowMs();
		it->second.verified = true;
	}
}

// -----------------------------------------------------------------------------
// STUN handling
// -----------------------------------------------------------------------------

void NATTraversal::handleStunPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) {
	STUNMessage message;
	if (!message.decode(data)) {
		nativeLog("NAT: Received malformed STUN packet");
		return;
	}

	switch (message.getType()) {
		case STUNMessageType::BindingResponse: {
			std::string key = transactionKey(message.getTransactionId());
			{
				std::lock_guard<std::mutex> lock(pending_mutex_);
				auto it = pending_transactions_.find(key);
				if (it != pending_transactions_.end()) {
					it->second.response = data;
					it->second.completed = true;
					pending_cv_.notify_all();
				}
			}
			break;
		}
		case STUNMessageType::BindingIndication: {
			std::lock_guard<std::mutex> lock(peers_mutex_);
			for (auto& [_, peer] : peers_by_id_) {
				if (peer.external_ip == ip && peer.external_port == port) {
					peer.last_heartbeat_ms = systemNowMs();
					peer.missed_heartbeats = 0;
					break;
				}
			}
			break;
		}
		case STUNMessageType::BindingRequest: {
			IUdpConnectionManager* manager = connection_manager_.load();
			if (!manager) {
				break;
			}

			STUNMessage response;
			response.setType(STUNMessageType::BindingResponse);
			response.setTransactionId(message.getTransactionId());

			std::vector<uint8_t> attr;
			attr.reserve(8);
			attr.push_back(0x00);
			attr.push_back(0x01);

			uint16_t xor_port = static_cast<uint16_t>(port) ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
			attr.push_back(static_cast<uint8_t>((xor_port >> 8) & 0xFF));
			attr.push_back(static_cast<uint8_t>(xor_port & 0xFF));

			uint32_t addr = inet_addr(ip.c_str());
			uint32_t xor_addr = ntohl(addr) ^ STUN_MAGIC_COOKIE;

			attr.push_back(static_cast<uint8_t>((xor_addr >> 24) & 0xFF));
			attr.push_back(static_cast<uint8_t>((xor_addr >> 16) & 0xFF));
			attr.push_back(static_cast<uint8_t>((xor_addr >> 8) & 0xFF));
			attr.push_back(static_cast<uint8_t>(xor_addr & 0xFF));

			response.addAttribute(STUNAttributeType::XorMappedAddress, attr);
			manager->sendRawPacket(ip, port, response.encode());
			break;
		}
		default:
			nativeLog("NAT: Ignoring STUN message type");
			break;
	}
}

// -----------------------------------------------------------------------------
// Heartbeats & maintenance
// -----------------------------------------------------------------------------

void NATTraversal::sendHeartbeats() {
	IUdpConnectionManager* manager = connection_manager_.load();
	if (!manager) {
		return;
	}

	Options options_copy;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		options_copy = options_;
	}

	if (heartbeat_payload_.empty()) {
		heartbeat_payload_ = makeHeartbeatPayload();
	}

	const int64_t now_ms = systemNowMs();
	std::vector<PeerAddress> peers_snapshot;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		peers_snapshot.reserve(peers_by_id_.size());
		for (const auto& [_, peer] : peers_by_id_) {
			peers_snapshot.push_back(peer);
		}
	}

	for (const auto& peer : peers_snapshot) {
		manager->sendRawPacket(peer.external_ip, peer.external_port, heartbeat_payload_);
	}

	// Track heartbeats sent
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.heartbeats_sent += static_cast<uint64_t>(peers_snapshot.size());
	}

	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		for (auto& [peer_id, peer] : peers_by_id_) {
			if (now_ms - peer.last_heartbeat_ms > options_copy.heartbeat_timeout_ms) {
				peer.missed_heartbeats = std::min(options_copy.max_missed_heartbeats + 1, peer.missed_heartbeats + 1);
			}
		}
	}
}

void NATTraversal::receiveHeartbeat(const std::string& peer_id) {
	// Track heartbeat received
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.heartbeats_received++;
	}
	
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto it = peers_by_id_.find(peer_id);
	if (it != peers_by_id_.end()) {
		it->second.last_heartbeat_ms = systemNowMs();
		it->second.missed_heartbeats = 0;
	}
}

void NATTraversal::startHeartbeatThread() {
	stopHeartbeatThread();
	{
		std::lock_guard<std::mutex> lock(heartbeat_mutex_);
		heartbeat_stop_requested_ = false;
	}
	heartbeat_thread_ = std::thread([this]() {
		try {
			heartbeatLoop();
		} catch (const std::exception& e) {
			nativeLog(std::string("NAT: Heartbeat thread terminated by exception: ") + e.what());
		} catch (...) {
			nativeLog("NAT: Heartbeat thread terminated by unknown exception");
		}
	});
}

void NATTraversal::stopHeartbeatThread() {
	{
		std::lock_guard<std::mutex> lock(heartbeat_mutex_);
		heartbeat_stop_requested_ = true;
	}
	heartbeat_cv_.notify_all();
	if (heartbeat_thread_.joinable()) {
		heartbeat_thread_.join();
	}
	{
		std::lock_guard<std::mutex> lock(heartbeat_mutex_);
		heartbeat_stop_requested_ = false;
	}
}

void NATTraversal::heartbeatLoop() {
	while (!shutdown_requested_.load()) {
		sendHeartbeats();

		int interval = 15;
		{
			std::lock_guard<std::mutex> lock(options_mutex_);
			interval = std::max(1, options_.heartbeat_interval_sec);
		}

		std::unique_lock<std::mutex> lock(heartbeat_mutex_);
		if (heartbeat_cv_.wait_for(lock,
				std::chrono::seconds(interval),
				[this]() { return heartbeat_stop_requested_ || shutdown_requested_.load(); })) {
			break;
		}
	}
}

void NATTraversal::startMaintenanceThread() {
	stopMaintenanceThread();
	{
		std::lock_guard<std::mutex> lock(maintenance_mutex_);
		maintenance_stop_requested_ = false;
	}
	maintenance_thread_ = std::thread([this]() {
		try {
			maintenanceLoop();
		} catch (const std::exception& e) {
			nativeLog(std::string("NAT: Maintenance thread terminated by exception: ") + e.what());
		} catch (...) {
			nativeLog("NAT: Maintenance thread terminated by unknown exception");
		}
	});
}

void NATTraversal::stopMaintenanceThread() {
	{
		std::lock_guard<std::mutex> lock(maintenance_mutex_);
		maintenance_stop_requested_ = true;
	}
	maintenance_cv_.notify_all();
	if (maintenance_thread_.joinable()) {
		maintenance_thread_.join();
	}
	{
		std::lock_guard<std::mutex> lock(maintenance_mutex_);
		maintenance_stop_requested_ = false;
	}
}

void NATTraversal::maintenanceLoop() {
	while (!shutdown_requested_.load()) {
		Options options_snapshot;
		{
			std::lock_guard<std::mutex> lock(options_mutex_);
			options_snapshot = options_;
		}

		const int interval = std::max(5, options_snapshot.cleanup_interval_sec);
		std::unique_lock<std::mutex> lock(maintenance_mutex_);
		if (maintenance_cv_.wait_for(lock,
				std::chrono::seconds(interval),
				[this]() { return maintenance_stop_requested_ || shutdown_requested_.load(); })) {
			break;
		}
		lock.unlock();

		const int64_t now_ms = systemNowMs();
		cleanupStalePeersLocked(now_ms, options_snapshot);
		cleanupStaleMappingsLocked(now_ms);
		renewLeasesLocked(now_ms);
		reloadConfiguration();
	}
}

void NATTraversal::cleanupStalePeersLocked(int64_t now_ms, const Options& options_snapshot) {
	size_t peer_count = 0;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);

		for (auto it = peers_by_id_.begin(); it != peers_by_id_.end();) {
			if (it->second.missed_heartbeats > options_snapshot.max_missed_heartbeats ||
				now_ms - it->second.last_heartbeat_ms > options_snapshot.heartbeat_timeout_ms) {
				nativeLog("NAT: Removing stale peer " + it->first);
				it = peers_by_id_.erase(it);
			} else {
				++it;
			}
		}
		peer_count = peers_by_id_.size();
	}

	// Update peer count metric
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.active_peers = static_cast<int>(peer_count);
	}
}

void NATTraversal::cleanupStaleMappingsLocked(int64_t now_ms) {
	std::lock_guard<std::mutex> lock(mapping_mutex_);
	for (auto it = mappings_by_id_.begin(); it != mappings_by_id_.end();) {
		const auto& mapping = it->second;
		const int64_t age_ms = now_ms - mapping.created_at_ms;
		const int64_t lease_ms = mapping.lease_duration_seconds * 1000;
		if (lease_ms > 0 && age_ms > lease_ms) {
			nativeLog("NAT: Expiring port mapping " + mapping.mapping_id);
			it = mappings_by_id_.erase(it);
		} else {
			++it;
		}
	}
}

void NATTraversal::renewLeasesLocked(int64_t now_ms) {
	std::lock_guard<std::mutex> lock(mapping_mutex_);
	for (auto& [_, mapping] : mappings_by_id_) {
		const int64_t lease_ms = mapping.lease_duration_seconds * 1000;
		if (lease_ms <= 0) continue;
		const int64_t age_ms = now_ms - mapping.created_at_ms;
		if (age_ms > (lease_ms * 4) / 5) {
			nativeLog("NAT: Lease renewal scheduled for mapping " + mapping.mapping_id);
			mapping.created_at_ms = now_ms;
		}
	}
}

// -----------------------------------------------------------------------------
// Punch thread pool
// -----------------------------------------------------------------------------

void NATTraversal::startPunchThreadPool() {
	int threads = 1;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		threads = std::max(1, options_.punch_thread_pool_size);
	}

	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		punch_shutdown_ = false;
	}

	punch_workers_.reserve(threads);
	for (int i = 0; i < threads; ++i) {
		punch_workers_.emplace_back(&NATTraversal::punchWorkerLoop, this);
	}
	current_punch_worker_count_ = threads;

	nativeLog("NAT: Started punch thread pool with " + std::to_string(threads) + " worker(s)");
}

void NATTraversal::stopPunchThreadPool() {
	{
		std::lock_guard<std::mutex> lock(punch_mutex_);
		punch_shutdown_ = true;
	}
	punch_cv_.notify_all();

	for (auto& worker : punch_workers_) {
		if (worker.joinable()) {
			worker.join();
		}
	}
	punch_workers_.clear();
	current_punch_worker_count_ = 0;
}

void NATTraversal::clearPunchQueue() {
	std::lock_guard<std::mutex> lock(punch_mutex_);
	std::queue<PeerAddress> empty;
	std::swap(punch_queue_, empty);
	punch_queued_peers_.clear();
	punch_inflight_peers_.clear();
	punch_reschedule_latest_.clear();
}

// -----------------------------------------------------------------------------
// NAT detection
// -----------------------------------------------------------------------------

NATType NATTraversal::detectNatViaStunServers(std::string& external_ip, uint16_t& external_port) {
	std::vector<STUNClient::STUNServer> servers;
	int timeout_ms = 2000;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		timeout_ms = options_.stun_timeout_ms;
	}
	{
		std::lock_guard<std::mutex> lock(stun_mutex_);
		for (const auto& server : stun_servers_) {
			STUNClient::STUNServer s;
			s.hostname = server.hostname;
			s.port = server.port;
			s.timeout_ms = std::max(500, timeout_ms);
			servers.push_back(s);
		}
	}

	if (servers.empty()) {
		nativeLog("NAT: No STUN servers configured for detection");
		return NATType::Unknown;
	}

	return stun_client_.detectNATType(servers, external_ip, external_port);
}

NATInfo NATTraversal::detectNATType() {
	if (shutdown_requested_.load(std::memory_order_acquire)) {
		NATInfo info;
		info.local_port = local_port_;
		{
			std::lock_guard<std::mutex> lock(options_mutex_);
			info.supports_upnp = options_.upnp_enabled;
			info.supports_stun = options_.stun_enabled;
		}
		info.nat_type = NATType::Unknown;
		return info;
	}

	Options options_copy;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		options_copy = options_;
	}

	NATInfo info;
	info.local_port = local_port_;
	info.supports_upnp = options_copy.upnp_enabled;
	info.supports_stun = options_copy.stun_enabled;

	if (!options_copy.stun_enabled) {
		nativeLog("NAT: STUN detection disabled by configuration");
		return info;
	}

	std::string external_ip;
	uint16_t external_port = 0;
	
	// Track STUN probe attempt
	auto start_time = std::chrono::steady_clock::now();
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.stun_requests_sent++;
		metrics_.detection_count++;
	}
	
	NATType type = detectNatViaStunServers(external_ip, external_port);
	const std::string stunclient_ip = external_ip;
	const uint16_t stunclient_port = external_port;

	// IMPORTANT: The STUNClient path may use an ephemeral socket, producing a mapped port that
	// is NOT usable for inbound packets to our listening UDP socket.
	// If we have a connection manager, prefer measuring the external mapping using the already-bound
	// transport socket (correct local port).
	if (options_copy.stun_enabled) {
		IUdpConnectionManager* manager = connection_manager_.load();
		std::vector<STUNServer> servers_snapshot;
		{
			std::lock_guard<std::mutex> lock(stun_mutex_);
			servers_snapshot = stun_servers_;
		}
		if (manager && !servers_snapshot.empty()) {
			const int timeout_ms = std::max(500, options_copy.stun_timeout_ms);
			for (const auto& server : servers_snapshot) {
				std::string server_ip;
				if (!resolveIpv4(server.hostname, static_cast<uint16_t>(server.port), server_ip)) {
					continue;
				}

				STUNMessage request;
				request.setType(STUNMessageType::BindingRequest);
				std::vector<uint8_t> request_bytes = request.encode();
				const std::string tx_key = transactionKey(request.getTransactionId());

				{
					std::lock_guard<std::mutex> lock(pending_mutex_);
					pending_transactions_[tx_key] = PendingTransaction();
				}

				manager->sendRawPacket(server_ip, server.port, request_bytes);

				std::vector<uint8_t> response_bytes;
				bool got = false;
				{
					std::unique_lock<std::mutex> lock(pending_mutex_);
					if (pending_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
						if (shutdown_requested_.load(std::memory_order_acquire)) {
							return true;
						}
						auto it = pending_transactions_.find(tx_key);
						return it != pending_transactions_.end() && it->second.completed;
					})) {
						if (shutdown_requested_.load(std::memory_order_acquire)) {
							pending_transactions_.erase(tx_key);
							break;
						}
						auto it = pending_transactions_.find(tx_key);
						if (it != pending_transactions_.end()) {
							response_bytes = it->second.response;
							got = true;
						}
					}
					pending_transactions_.erase(tx_key);
				}

				if (!got) {
					continue;
				}

				STUNMessage response;
				if (!response.decode(response_bytes)) {
					continue;
				}
				STUNAddress mapped;
				bool has = response.getXorMappedAddress(mapped);
				if (!has) {
					has = response.getMappedAddress(mapped);
				}
				if (!has || mapped.ip.empty() || mapped.port == 0) {
					continue;
				}

				// We only support IPv4 transports today.
				if (mapped.ip.find(':') != std::string::npos) {
					continue;
				}

				external_ip = mapped.ip;
				external_port = static_cast<uint16_t>(mapped.port);
				if (!stunclient_ip.empty() && (external_ip != stunclient_ip || external_port != stunclient_port)) {
					nativeLog(
						"NAT: STUN mapped address override via bound socket: " +
						stunclient_ip + ":" + std::to_string(stunclient_port) +
						" -> " + external_ip + ":" + std::to_string(external_port));
				}
				break;
			}
		}
	}
	
	// Track probe result and duration
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		if (!external_ip.empty()) {
			metrics_.stun_responses_received++;
		} else {
			metrics_.stun_errors++;
		}
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - start_time).count();
		metrics_.last_detection_ms = elapsed;
		metrics_.last_updated_ms = systemNowMs();
	}

	// If STUN returns an IPv6 external mapping but the rest of the stack treats
	// IPv6 endpoints as non-connectable (IPv4-only transport), do not publish an
	// unusable external address. This avoids signaling advertising a network_id
	// that peers will refuse to connect to.
	bool suppressed_ipv6 = false;
	std::string suppressed_ip;
	uint16_t suppressed_port = 0;
	if (!external_ip.empty() && external_ip.find(':') != std::string::npos) {
		suppressed_ipv6 = true;
		suppressed_ip = external_ip;
		suppressed_port = external_port;
		external_ip.clear();
		external_port = 0;
	}

	info.nat_type = type;
	info.external_ip = external_ip;
	info.external_port = external_port;
	info.detected_at_ms = systemNowMs();

	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		nat_info_ = info;
	}

	if (!external_ip.empty()) {
		nativeLog("NAT: Detected NAT type " + natTypeToString(type) + " external=" + external_ip + ":" + std::to_string(external_port));
	} else if (suppressed_ipv6) {
		nativeLog(
			"NAT: Detected NAT type " + natTypeToString(type) + " external=" +
			suppressed_ip + ":" + std::to_string(suppressed_port) +
			" (IPv6) but transport is IPv4-only; not publishing external endpoint");
	} else {
		nativeLog("NAT: NAT detection failed to resolve external address");
	}

    // Try TURN allocation if enabled
    if (options_copy.turn_enabled) {
        TurnClient turnClient(options_copy.turn_config);
        TurnAllocation allocation;
        if (turnClient.allocate(allocation)) {
            info.relay_ip = allocation.relayed_ip;
            info.relay_port = allocation.relayed_port;
            nativeLog("NAT: TURN Allocation successful. Relay: " + allocation.relayed_ip + ":" + std::to_string(allocation.relayed_port));
        } else {
            nativeLog("NAT: TURN Allocation failed");
        }
    }

	return info;
}

NATInfo NATTraversal::getNATInfo() const {
	std::lock_guard<std::mutex> lock(nat_info_mutex_);
	return nat_info_;
}

bool NATTraversal::testConnectivity() {
	NATInfo info = detectNATType();
	return info.supports_stun || info.supports_upnp;
}

// -----------------------------------------------------------------------------
// STUN server management
// -----------------------------------------------------------------------------

void NATTraversal::addSTUNServer(const STUNServer& server) {
	std::lock_guard<std::mutex> lock(stun_mutex_);
	stun_servers_.push_back(server);
	nativeLog("NAT: Added STUN server " + serverToString(server));
}

std::vector<STUNServer> NATTraversal::getSTUNServers() const {
	std::lock_guard<std::mutex> lock(stun_mutex_);
	return stun_servers_;
}

// -----------------------------------------------------------------------------
// Connection validation and keepalive
// -----------------------------------------------------------------------------

bool NATTraversal::validatePeerConnection(const std::string& peer_id) {
	IUdpConnectionManager* manager = connection_manager_.load();
	if (!manager) {
		nativeLog("NAT: validatePeerConnection - no connection manager");
		return false;
	}
	
	PeerAddress peer;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		auto it = peers_by_id_.find(peer_id);
		if (it == peers_by_id_.end()) {
			nativeLog("NAT: validatePeerConnection - peer not found: " + peer_id);
			return false;
		}
		peer = it->second;
	}
	
	// Send a STUN binding request as a connectivity check
	STUNMessage request;
	request.setType(STUNMessageType::BindingRequest);
	std::vector<uint8_t> payload = request.encode();
	std::string tx_key = transactionKey(request.getTransactionId());
	
	// Register pending transaction
	{
		std::lock_guard<std::mutex> lock(pending_mutex_);
		pending_transactions_[tx_key] = PendingTransaction();
	}
	
	int64_t send_time = systemNowMs();
	manager->sendRawPacket(peer.external_ip, peer.external_port, payload);
	
	// Wait for response with timeout
	bool success = false;
	int32_t latency = -1;
	{
		std::unique_lock<std::mutex> lock(pending_mutex_);
		if (pending_cv_.wait_for(lock, std::chrono::milliseconds(2000), [&]() {
			auto it = pending_transactions_.find(tx_key);
			return it != pending_transactions_.end() && it->second.completed;
		})) {
			success = true;
			latency = static_cast<int32_t>(systemNowMs() - send_time);
			pending_transactions_.erase(tx_key);
		} else {
			pending_transactions_.erase(tx_key);
		}
	}
	
	// Update peer metrics
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		auto it = peers_by_id_.find(peer_id);
		if (it != peers_by_id_.end()) {
			it->second.packets_sent++;
			if (success) {
				it->second.packets_received++;
				it->second.latency_ms = latency;
				it->second.last_validated_ms = systemNowMs();
				it->second.verified = true;
				
				// Update moving average (simple exponential moving average)
				if (it->second.avg_latency_ms < 0) {
					it->second.avg_latency_ms = latency;
				} else {
					it->second.avg_latency_ms = (it->second.avg_latency_ms * 7 + latency) / 8;
				}
				
				// Calculate jitter (variation from average)
				int32_t diff = std::abs(latency - it->second.avg_latency_ms);
				it->second.jitter_ms = (it->second.jitter_ms * 7 + diff) / 8;
			}
			
			// Update packet loss rate
			if (it->second.packets_sent > 0) {
				it->second.packet_loss_rate = 1.0f - 
					(static_cast<float>(it->second.packets_received) / 
					 static_cast<float>(it->second.packets_sent));
			}
		}
	}
	
	nativeLog("NAT: Connectivity check for " + peer_id + ": " + 
	          (success ? ("OK, RTT=" + std::to_string(latency) + "ms") : "FAILED"));
	return success;
}

bool NATTraversal::sendKeepalive(const std::string& peer_id) {
	IUdpConnectionManager* manager = connection_manager_.load();
	if (!manager) {
		return false;
	}
	
	PeerAddress peer;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		auto it = peers_by_id_.find(peer_id);
		if (it == peers_by_id_.end()) {
			return false;
		}
		peer = it->second;
	}
	
	// Send a STUN binding indication (no response expected)
	if (heartbeat_payload_.empty()) {
		heartbeat_payload_ = makeHeartbeatPayload();
	}
	
	manager->sendRawPacket(peer.external_ip, peer.external_port, heartbeat_payload_);
	
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		auto it = peers_by_id_.find(peer_id);
		if (it != peers_by_id_.end()) {
			it->second.packets_sent++;
		}
	}
	
	return true;
}

int NATTraversal::getPeerLatencyMs(const std::string& peer_id) const {
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto it = peers_by_id_.find(peer_id);
	if (it != peers_by_id_.end()) {
		return it->second.avg_latency_ms;
	}
	return -1;
}

bool NATTraversal::isPeerReachable(const std::string& peer_id) const {
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto it = peers_by_id_.find(peer_id);
	if (it == peers_by_id_.end()) {
		return false;
	}
	
	const auto& peer = it->second;
	
	// Consider peer unreachable if:
	// - Never validated
	// - Last validation was too long ago (> 60 seconds)
	// - Packet loss rate is too high (> 50%)
	// - Too many missed heartbeats
	
	if (!peer.verified) {
		return false;
	}
	
	const int64_t now_ms = systemNowMs();
	const int64_t max_stale_ms = 60000;  // 60 seconds
	
	if (peer.last_validated_ms > 0 && (now_ms - peer.last_validated_ms) > max_stale_ms) {
		return false;
	}
	
	if (peer.packet_loss_rate > 0.5f) {
		return false;
	}
	
	Options options_copy;
	{
		std::lock_guard<std::mutex> lock2(options_mutex_);
		options_copy = options_;
	}
	
	if (peer.missed_heartbeats > options_copy.max_missed_heartbeats) {
		return false;
	}
	
	return true;
}

// -----------------------------------------------------------------------------
// Port mapping (controller-driven)
// -----------------------------------------------------------------------------

bool NATTraversal::attemptUPnPMapping(uint16_t internal_port,
								  uint16_t external_port,
								  const std::string& protocol) {
	Options options_copy;
	{
		std::lock_guard<std::mutex> lock(options_mutex_);
		options_copy = options_;
	}

	if (!options_copy.upnp_enabled) {
		nativeLog("NAT: UPnP mapping disabled by configuration");
		return false;
	}

	std::shared_ptr<IUpnpController> controller;
	{
		std::lock_guard<std::mutex> lock(upnp_mutex_);
		controller = upnp_controller_;
	}

	if (!controller) {
		nativeLog("NAT: No UPnP controller installed");
		return false;
	}

	if (!controller->isAvailable()) {
		nativeLog("NAT: UPnP controller reported unavailable");
		return false;
	}

	std::string mapping_id;
	if (!controller->addPortMapping(internal_port,
			external_port,
			protocol,
			options_copy.upnp_lease_duration_sec,
			mapping_id)) {
		nativeLog("NAT: UPnP port mapping failed for " + std::to_string(internal_port) + "->" + std::to_string(external_port));
		return false;
	}

	if (mapping_id.empty()) {
		mapping_id = protocol + "_" + std::to_string(external_port);
	}

	std::string detected_external_ip;
	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		detected_external_ip = nat_info_.external_ip;
	}

	NATMapping mapping;
	mapping.internal_ip = "0.0.0.0";
	mapping.internal_port = internal_port;
	mapping.external_ip = detected_external_ip.empty() ? std::string("0.0.0.0") : detected_external_ip;
	mapping.external_port = external_port;
	mapping.protocol = protocol;
	mapping.lease_duration_seconds = options_copy.upnp_lease_duration_sec;
	mapping.created_at_ms = systemNowMs();
	mapping.mapping_id = mapping_id;

	size_t mapping_count = 0;
	{
		std::lock_guard<std::mutex> lock(mapping_mutex_);
		mappings_by_id_[mapping.mapping_id] = mapping;
		mapping_count = mappings_by_id_.size();
	}
	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		nat_info_.supports_upnp = true;
	}

	// Update UPnP mapping metric
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.active_upnp_mappings = static_cast<int>(mapping_count);
		metrics_.upnp_mapping_successes++;
		metrics_.last_updated_ms = systemNowMs();
	}

	nativeLog("NAT: UPnP mapping established id=" + mapping.mapping_id);
	return true;
}

bool NATTraversal::removeUPnPMapping(const std::string& mapping_id) {
	std::shared_ptr<IUpnpController> controller;
	{
		std::lock_guard<std::mutex> lock(upnp_mutex_);
		controller = upnp_controller_;
	}
	if (controller) {
		controller->removePortMapping(mapping_id);
	}

	size_t mapping_count = 0;
	bool removed = false;
	{
		std::lock_guard<std::mutex> lock(mapping_mutex_);
		if (mappings_by_id_.erase(mapping_id) > 0) {
			removed = true;
			mapping_count = mappings_by_id_.size();
		}
	}
	
	if (removed) {
		// Update UPnP mapping metric
		{
			std::lock_guard<std::mutex> lock(metrics_mutex_);
			metrics_.active_upnp_mappings = static_cast<int>(mapping_count);
			metrics_.last_updated_ms = systemNowMs();
		}
		nativeLog("NAT: Removed UPnP mapping " + mapping_id);
		return true;
	}
	return false;
}

NATMapping NATTraversal::getMappingForPort(uint16_t port) const {
	std::lock_guard<std::mutex> lock(mapping_mutex_);
	for (const auto& [_, mapping] : mappings_by_id_) {
		if (mapping.internal_port == port) {
			return mapping;
		}
	}
	return NATMapping();
}

// -----------------------------------------------------------------------------
// Metrics and monitoring
// -----------------------------------------------------------------------------

NATMetrics NATTraversal::getMetrics() const {
	NATMetrics result;
	
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		result = metrics_;
	}
	
	// Update computed fields
	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		result.detected_nat_type = nat_info_.nat_type;
		result.last_detection_ms = nat_info_.detected_at_ms;
	}
	
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		result.active_peers = static_cast<int>(peers_by_id_.size());
		result.verified_peers = 0;
		result.unreachable_peers = 0;
		
		Options options_copy;
		{
			std::lock_guard<std::mutex> lock2(options_mutex_);
			options_copy = options_;
		}
		
		for (const auto& [_, peer] : peers_by_id_) {
			if (peer.verified) {
				result.verified_peers++;
			}
			if (peer.missed_heartbeats > options_copy.max_missed_heartbeats) {
				result.unreachable_peers++;
			}
		}
	}
	
	{
		std::lock_guard<std::mutex> lock(mapping_mutex_);
		result.active_upnp_mappings = static_cast<int>(mappings_by_id_.size());
	}
	
	// Calculate success rates
	if (result.hole_punch_attempts > 0) {
		result.hole_punch_success_rate = 
			static_cast<float>(result.hole_punch_successes) / 
			static_cast<float>(result.hole_punch_attempts);
	}
	
	result.last_updated_ms = systemNowMs();
	if (init_time_ms_ > 0) {
		result.uptime_ms = result.last_updated_ms - init_time_ms_;
	}
	
	return result;
}

void NATTraversal::resetMetrics() {
	std::lock_guard<std::mutex> lock(metrics_mutex_);
	metrics_ = NATMetrics();
	init_time_ms_ = systemNowMs();
	nativeLog("NAT: Metrics reset");
}

// -----------------------------------------------------------------------------
// JSON snapshot
// -----------------------------------------------------------------------------

json NATTraversal::toJSON() const {
	json result;
	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		result["nat_type"] = natTypeToString(nat_info_.nat_type);
		result["external_ip"] = nat_info_.external_ip;
		result["external_port"] = nat_info_.external_port;
		result["supports_stun"] = nat_info_.supports_stun;
		result["supports_upnp"] = nat_info_.supports_upnp;
		result["detected_at_ms"] = nat_info_.detected_at_ms;
	}

	{
		std::lock_guard<std::mutex> lock(stun_mutex_);
		json servers = json::array();
		for (const auto& server : stun_servers_) {
			json entry;
			entry["hostname"] = server.hostname;
			entry["port"] = server.port;
			entry["protocol"] = server.protocol;
			servers.push_back(entry);
		}
		result["stun_servers"] = servers;
	}
	
	// Add metrics to JSON output
	{
		NATMetrics metrics = getMetrics();
		json metrics_json;
		metrics_json["stun_requests_sent"] = metrics.stun_requests_sent;
		metrics_json["stun_responses_received"] = metrics.stun_responses_received;
		metrics_json["stun_timeouts"] = metrics.stun_timeouts;
		metrics_json["avg_stun_latency_ms"] = metrics.avg_stun_latency_ms;
		metrics_json["hole_punch_attempts"] = metrics.hole_punch_attempts;
		metrics_json["hole_punch_successes"] = metrics.hole_punch_successes;
		metrics_json["hole_punch_success_rate"] = metrics.hole_punch_success_rate;
		metrics_json["active_peers"] = metrics.active_peers;
		metrics_json["verified_peers"] = metrics.verified_peers;
		metrics_json["unreachable_peers"] = metrics.unreachable_peers;
		metrics_json["heartbeats_sent"] = metrics.heartbeats_sent;
		metrics_json["heartbeats_received"] = metrics.heartbeats_received;
		metrics_json["uptime_ms"] = metrics.uptime_ms;
		result["metrics"] = metrics_json;
	}

	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		json peers = json::array();
		for (const auto& [_, peer] : peers_by_id_) {
			json entry;
			entry["peer_id"] = peer.peer_id;
			entry["network_id"] = peer.network_id;
			entry["external_ip"] = peer.external_ip;
			entry["external_port"] = peer.external_port;
			entry["last_heartbeat_ms"] = peer.last_heartbeat_ms;
			entry["missed_heartbeats"] = peer.missed_heartbeats;
			entry["last_successful_punch_ms"] = peer.last_successful_punch_ms;
			peers.push_back(entry);
		}
		result["registered_peers"] = peers;
	}

	{
		std::lock_guard<std::mutex> lock(mapping_mutex_);
		json mappings = json::array();
		for (const auto& [_, mapping] : mappings_by_id_) {
			json entry;
			entry["mapping_id"] = mapping.mapping_id;
			entry["internal_port"] = mapping.internal_port;
			entry["external_port"] = mapping.external_port;
			entry["protocol"] = mapping.protocol;
			entry["created_at_ms"] = mapping.created_at_ms;
			entry["lease_duration_seconds"] = mapping.lease_duration_seconds;
			mappings.push_back(entry);
		}
		result["active_mappings"] = mappings;
	}

	return result;
}

// -----------------------------------------------------------------------------
// Local network discovery
// -----------------------------------------------------------------------------

void NATTraversal::sendDiscoveryPackets() {
	if (shutdown_requested_.load()) {
		return;
	}
	
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		nativeLog("NAT: Discovery socket creation failed: " + std::string(strerror(errno)));
		return;
	}

	int broadcast = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
		nativeLog("NAT: Failed to enable broadcast: " + std::string(strerror(errno)));
		close(sock);
		return;
	}
	
	// Set socket timeout for any receives
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	// Build discovery packet with structured data
	json discovery_payload;
	discovery_payload["type"] = "DISCOVERY";
	discovery_payload["port"] = local_port_;
	discovery_payload["timestamp"] = systemNowMs();
	
	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		if (!nat_info_.external_ip.empty()) {
			discovery_payload["external_ip"] = nat_info_.external_ip;
			discovery_payload["external_port"] = nat_info_.external_port;
			discovery_payload["nat_type"] = natTypeToString(nat_info_.nat_type);
		}
	}
	
	std::string payload = discovery_payload.dump();

	// Broadcast to common discovery ports
	const std::vector<uint16_t> discovery_ports = {local_port_, 5353, 6881};
	
	for (uint16_t port : discovery_ports) {
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr("255.255.255.255");
		
		ssize_t sent = sendto(sock, payload.data(), payload.size(), 0, 
		                      reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
		if (sent < 0) {
			nativeLog("NAT: Discovery send failed on port " + std::to_string(port) + 
			          ": " + strerror(errno));
		}
	}
	
	close(sock);
	nativeLog("NAT: Discovery broadcast emitted on port " + std::to_string(local_port_));
	
	// Track discovery broadcast
	{
		std::lock_guard<std::mutex> lock(metrics_mutex_);
		metrics_.discovery_broadcasts_sent++;
	}
}

void NATTraversal::updateLocalPeersFromDiscovery() {
	if (shutdown_requested_.load()) {
		return;
	}
	
	// Listen briefly for discovery responses
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		nativeLog("NAT: Discovery listen socket failed: " + std::string(strerror(errno)));
		return;
	}
	
	// Allow address reuse
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	
	// Bind to local port
	sockaddr_in bind_addr{};
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = htons(local_port_);
	bind_addr.sin_addr.s_addr = INADDR_ANY;
	
	if (bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
		// Non-fatal - port might be in use by main connection manager
		close(sock);
		return;
	}
	
	// Set short timeout
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 500000;  // 500ms
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	
	// Try to receive any pending discovery responses
	char buffer[1024];
	sockaddr_in from_addr{};
	socklen_t from_len = sizeof(from_addr);
	
	int peers_found = 0;
	const int max_reads = 10;
	
	for (int i = 0; i < max_reads && !shutdown_requested_.load(); ++i) {
		ssize_t received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
		                            reinterpret_cast<sockaddr*>(&from_addr), &from_len);
		if (received <= 0) {
			break;
		}
		
		buffer[received] = '\0';
		
		try {
			json msg = json::parse(buffer);
			if (msg.value("type", "") == "DISCOVERY") {
				char ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &from_addr.sin_addr, ip_str, sizeof(ip_str));
				
				PeerAddress peer;
				peer.internal_ip = ip_str;
				peer.internal_port = msg.value("port", 0);
				peer.external_ip = msg.value("external_ip", std::string(ip_str));
				peer.external_port = msg.value("external_port", peer.internal_port);
				peer.nat_type = msg.value("nat_type", "Unknown");
				peer.discovered_at_ms = systemNowMs();
				peer.peer_id = "local_" + std::string(ip_str) + "_" + 
				               std::to_string(peer.internal_port);
				peer.network_id = "local";
				
				registerPeer(peer);
				peers_found++;
			}
		} catch (const json::exception& e) {
			// Ignore malformed packets
		}
	}
	
	close(sock);
	if (peers_found > 0) {
		nativeLog("NAT: Discovered " + std::to_string(peers_found) + " local peer(s)");
	}
}

void NATTraversal::sendNetworkBroadcast() {
	if (shutdown_requested_.load()) {
		return;
	}
	
	// Get NAT info to include in broadcast
	NATInfo nat_copy;
	{
		std::lock_guard<std::mutex> lock(nat_info_mutex_);
		nat_copy = nat_info_;
	}
	
	// Build network announcement
	json announcement;
	announcement["type"] = "NAT_ANNOUNCE";
	announcement["local_port"] = local_port_;
	announcement["external_ip"] = nat_copy.external_ip;
	announcement["external_port"] = nat_copy.external_port;
	announcement["nat_type"] = natTypeToString(nat_copy.nat_type);
	announcement["supports_stun"] = nat_copy.supports_stun;
	announcement["supports_upnp"] = nat_copy.supports_upnp;
	announcement["timestamp"] = systemNowMs();
	
	std::string payload = announcement.dump();
	
	// Send to all registered peers
	IUdpConnectionManager* manager = connection_manager_.load();
	if (!manager) {
		nativeLog("NAT: sendNetworkBroadcast - no connection manager");
		return;
	}
	
	std::vector<PeerAddress> peers_copy;
	{
		std::lock_guard<std::mutex> lock(peers_mutex_);
		peers_copy.reserve(peers_by_id_.size());
		for (const auto& [_, peer] : peers_by_id_) {
			peers_copy.push_back(peer);
		}
	}
	
	int sent_count = 0;
	for (const auto& peer : peers_copy) {
		if (shutdown_requested_.load()) {
			break;
		}
		
		std::vector<uint8_t> data(payload.begin(), payload.end());
		manager->sendRawPacket(peer.external_ip, peer.external_port, data);
		sent_count++;
	}
	
	nativeLog("NAT: Network broadcast sent to " + std::to_string(sent_count) + " peer(s)");
}


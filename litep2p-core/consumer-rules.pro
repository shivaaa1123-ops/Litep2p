# Consumer ProGuard rules for :litep2p-core.
#
# The native library (liblitep2p.so) reaches back into Kotlin via JNI:
#   - LiteP2PNative: external fun declarations (native method lookup by name)
#   - NativeEvents: static callback methods invoked from engine threads
#   - PeerInfo: constructed reflectively from JNI (NewObject + cached ctor)
# None of these may be renamed, shrunk, or obfuscated.

-keep class com.zeengal.litep2p.core.LiteP2PNative { *; }
-keep class com.zeengal.litep2p.core.NativeEvents { *; }
-keep class com.zeengal.litep2p.core.PeerInfo { *; }

# Keep native method declarations in any core class.
-keepclasseswithmembernames class com.zeengal.litep2p.core.** {
    native <methods>;
}
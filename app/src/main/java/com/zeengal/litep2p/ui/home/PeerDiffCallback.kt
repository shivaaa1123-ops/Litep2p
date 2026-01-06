package com.zeengal.litep2p.ui.home

import androidx.recyclerview.widget.DiffUtil
import com.zeengal.litep2p.PeerInfo

class PeerDiffCallback(
    private val oldList: List<PeerInfo>,
    private val newList: List<PeerInfo>
) : DiffUtil.Callback() {

    override fun getOldListSize(): Int = oldList.size
    override fun getNewListSize(): Int = newList.size

    override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
        return oldList[oldItemPosition].id == newList[newItemPosition].id
    }

    override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
        return oldList[oldItemPosition] == newList[newItemPosition]
    }
}
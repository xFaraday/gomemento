# GoMemento
## Userspace EDR for linux/unix systems
### Maybe eventually add eBPF support to eventaully enter the linux kernel

Trending Linux EDR solutions typically operate in kernelspace to ensure granuality and accuracy of events.  However this approach introduces crashes, intrusive process hooking, and compatibility problems.  By staying in userspace, this EDR solution can operate in a variety of different kernel versions and distrobutions.

Functionality:
- /proc process monitoring
- Configuration file monitoring and restoration
- Network Profile Heuristics
- User command monitoring
- Red team artifact recovery
- Log monitoring

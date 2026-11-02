/*---[ ui-copilot-backend-win.c ]-------------------------------------------
 *
 * The real Windows backend for fs-copilot-smoke, under another name.
 *
 * The smoke's What-If section must not read the Windows Firewall of
 * whatever machine runs it: a CI runner on a Public network (where
 * StockFW's own reserved-source block decides an inbound from
 * 192.168.x.x, and on Windows a block wins over any allow) answers a
 * different -- correct -- question than the one the section asks.  On
 * Linux the section gets a network namespace of its own; Windows has
 * no such thing, so the smoke supplies fs_backend() itself and hands
 * out either this real backend (sections 1 to 6, unchanged) or a
 * Windows-shaped stand-in with a known state that refuses every write
 * (section 7).
 *
 * Built only into the Windows fs-copilot-smoke (CMakeLists.txt); never
 * part of StockFW.exe.
 *
 *----------------------------------------------------------------------*/
#define fs_backend fs_backend_real
#include "platform/windows/fs-backend-windows.c"

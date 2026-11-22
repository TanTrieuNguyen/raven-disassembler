import CoreGraphics
import Foundation
let pid = Int32(CommandLine.arguments[1])!
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
for row in list {
    if let owner = row[kCGWindowOwnerPID as String] as? Int32, owner == pid,
       let number = row[kCGWindowNumber as String] as? UInt32,
       let layer = row[kCGWindowLayer as String] as? Int, layer == 0 {
        print(number)
        exit(0)
    }
}
exit(1)

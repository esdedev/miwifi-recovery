# How Xiaomi router recovery works

Findings from the bootloader (U-Boot 2016.01) of the Xiaomi BE3600 2.5G, model code RD15
(Qualcomm IPQ5332). Other Xiaomi models of the same era use the same scheme, but their details
were not verified. Statements marked *(inferred)* are not confirmed from code.

## Entering recovery

- Hold the Reset button at power-on for 5 s. If the `restore_defaults` flag is set (right after a
  successful recovery), it takes 45 s.
- The status light blinks fast in orange (LED channel A) while the bootloader:
  1. pings `192.168.31.100` up to 4 times (a failure is only logged);
  2. requests an address over DHCP (vendor class `MSFT 5.0`);
  3. downloads the image over TFTP to RAM. The filename comes from the DHCP offer; without one it
     uses the hex of its own address (e.g. `C0A81F65.img` for 192.168.31.101). It asks only for the
     `timeout=5` option, so the transfer uses 512-byte blocks: 56,323 blocks for a 27.5 MiB image.

If DHCP fails, the whole sequence repeats.

## Image format (`HDR1`)

| Offset | Field |
|---|---|
| 0x00 | magic `HDR1` |
| 0x04 | u32 `sigoff`: length of the signed data |
| 0x08 | u32 CRC32 of `img[0x0c..end]`, initial value 0xffffffff, no final XOR |
| 0x0c | u16 image type (0x0c = encrypted, other key) |
| 0x0e | u16 model id (0x55 = RD15) |
| 0x10 | 32 × u32 offsets of sub-image headers |
| `sigoff` | u32 signature length (0x100), then the RSA-2048 signature |

Each sub-image header: u16 `0xbabe`, u32 flash address (`0xffffffff` = not flashed), u32 size,
name at +0x10, data at +0x30. The `xiaoqiang_version` sub-image is UCI text:
`option ROM '1.0.87'`, `option HARDWARE 'RD15'`, `option BUILDTIME '…'`, and others.

## Acceptance checks, in order

1. **Header**:
   - magic is `HDR1`, otherwise `TRX MAGIC error!`;
   - `sigoff` < 50 MiB, otherwise `File too large!`;
   - model id matches, otherwise `Mismatch trx model`;
   - the signature length is 0x100.
2. **CRC32**, then the **RSA signature** with Xiaomi's built-in public keys (e = 65537). A failure
   shows `Image verify failed!`. There is no bypass: see the audit in the companion research repository.
3. **Anti-rollback**:
   - The bootloader reads the installed version from the `miwifirom` property of the kernel image
     in the active system slot (`rootfs` or `rootfs_1`, from the `flag_last_success` variable).
     It reads the new version from `option ROM` in the image.
   - It turns each version into a number: `code = (code << 8) + (part & 0xff)` for each
     dot-separated part. A result below 0x10000 (major version 0, or fewer than three parts)
     counts as 0.
   - The update goes ahead only if `installed <= new`. Otherwise it shows `not permit upgrade!`.
   - If the installed version cannot be read (empty or damaged slot), it counts as 0 and any
     version is accepted.
4. **Flash**: `root.ubi` is written to both system slots. The version block is not flashed (it
   prints a harmless `Upgrade xiaoqiang_version fail!`).

The tool runs checks 1, the CRC part of 2, and 3 before sending the file. It cannot check the
signature, because that would need Xiaomi's keys and the check belongs to the router anyway. For
check 3 it needs you to type the installed version.

## Outcome

| Result | Light | Then |
|---|---|---|
| Success | blinks slowly (1 s on / 1 s off), channel B, blue *(inferred colour)* | waits forever; power-cycle it |
| Any refusal or error | steady orange (channel A); confirmed on an RD15 refusing a downgrade | waits forever; power-cycle it |

The bootloader does not reboot by itself in either case. That is why the tool asks you to look at
the light, then checks when the router answers at 192.168.31.1.

## The official tool

The official `MIWIFIRepairTool.x86.exe` contains the strings of Tftpd32 4.61 (built 24 Jan 2019)
plus `<RRT> by MIWIFI`, defaults `192.168.31.100`, pool `192.168.31.101`, and one HTTP request
(through libcurl) to `http://api.miwifi.com/data/tffp_rom_link_info`. That endpoint returns a
plain-text list of only three firmware links (Xiaomi Router 4, 4Q and 4C). One of the links has a
malformed `http://http://` prefix. The tool does not inspect the firmware it serves.

## Field test

On an RD15 running 1.0.87, the tool served the official 1.0.68 image without the installed
version being entered. Every network step worked, and so did the automatic IP setup on Windows.
The transfer completed. The router then refused the image: the light turned steady orange and
nothing was written. After a power cycle it started 1.0.87 again with its configuration intact.
After boot, a steady yellow light only means the WAN has no Internet connection.

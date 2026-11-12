# fbsurface

Internal framebuffer surface API for strat9. `no_std`, one optional heap
allocation for `OwnedSurface`, no OS dependency. The kernel instantiates it
with the SSE2 backend; the host runs the same code with the scalar backend.

```text
cargo test -p fbsurface
```

## Why

Before this crate, four surface types (`CanvasBuffer`, `HeapScreen`,
`SimpleDisplayAdapter`, `Framebuffer`) shared three damage models and two
colour conventions. `CanvasBuffer::blit_rect` documented a packed XRGB8888
source while `HeapScreen` carried a native format, so the compiler could not
stop a channel swap. This crate makes those states unrepresentable:

| Invariant | Enforced by |
|---|---|
| pitch covers the width, the buffer covers the pitch | `Canvas::new` / `Canvas::direct` |
| only 24/32 bpp reach the pixel backends | `Format::is_supported` |
| masks, shifts and width are consistent | `Format::is_valid` |
| bulk copies never reinterpret channels | `Canvas::blit` returns `FormatMismatch` |
| one conversion point | `Canvas::convert_from` → `Format::convert` |
| one clipping rule | `Rect::intersect` |
| one damage model | `RectSet` |
| FPU state saved around every draw | `PixelOps::guard` (kernel adapter) |
| refresh policy outside the surface | `framebuffer::Presenter` |

## Layers

| Type | Role |
|---|---|
| `Dims`, `Rect`, `RectSet<N>` | geometry and damage |
| `Format`, `Packed`, `Rgb` | layout and explicit conversion |
| `PixelOps`, `ScalarOps` | raw 32-bit fill/blit/blend |
| `Canvas<'a, O>` | validated mutable surface |
| `View<'a>`, `Source` | validated read-only surface and copy source |
| `OwnedSurface<O>` | heap back buffer with persistent damage |

`Canvas` borrows a `&mut [u8]` or points at MMIO (`Canvas::direct`). `View`
borrows a `&[u8]` or points at shared memory, which is how a client buffer or
a wire payload is blitted without an intermediate copy. Neither allocates.

`OwnedSurface` is the double-buffer half: a `Vec<u32>` (so the base is
4-byte aligned), pitch `width * 4`, and a damage set that survives across
drawing calls. `draw(|canvas| ...)` builds a short-lived `Canvas` and merges
the resulting damage back into the owner, so no surface holds a pointer into
its own backend and a caller cannot drop damage by accident. It replaces
`CanvasBuffer::back_buffer`; the scanout stays a `Canvas`. Paged storage
(`HeapScreen`) is out of scope: it is the thing R12 removes from the kernel.

## Kernel adapter

`strat9-kernel::framebuffer::surface` provides:

- `KernelOps`: `PixelOps` over `FramebufferOps`, with `FpuGuard` from every
  drawing call;
- `Presenter`: write-combining fence, `PRESENT_MIN_TICKS` rate limit and
  damage-driven present. `present`/`present_full` take a borrowed `Canvas`,
  `present_owned`/`present_full_owned` take a heap `OwnedSurface`, so the
  console can migrate without changing its refresh loop. Damage covering more
  than 60% of the panel is promoted to one full copy; direct `canvas_mut`
  writes are never overwritten by the back buffer; a format mismatch leaves
  the back damage untouched instead of dropping it;
- `From<PixelFormat> for Format` and back, so the legacy GOP format is
  converted at exactly one boundary.

## Migration map

| Old | New |
|---|---|
| `DirtyRect`, `DirtyRectSet`, `Damage` | `Rect`, `RectSet` |
| `CanvasBuffer::{width,height,pitch,bpp}` | `Canvas::{dims,pitch,format}` |
| `CanvasBuffer::dirty` | `Canvas::take_dirty` |
| `CanvasBuffer::fill_rect` | `Canvas::fill_rect` |
| `CanvasBuffer::blit_rect` | `Canvas::blit` (same format) or `Canvas::convert_from` |
| `&[u8]` source buffer | `View::new` then `Canvas::blit` |
| `CanvasBuffer::present` | `Presenter::present` |
| `CanvasBuffer::enable_back_buffer` | `OwnedSurface` + `Presenter::present_owned` |
| `CanvasBuffer::back_buffer` (`Option<Vec<u32>>`) | `OwnedSurface` |
| `CanvasBuffer::draw_to_back` | choose which surface the caller draws into |
| `CanvasBuffer::last_present_tick` | `Presenter` (private) |
| `FramebufferOps::blend` (unused) | `Canvas::blend_rect` |
| `PixelFormat` at the pixel API | `Format` |
| raw `u32` colour | `Packed` |

### Staged migration

1. **Done** — `fbsurface` crate, kernel adapter, `Presenter`, `OwnedSurface`.
2. **Next** — `arch/x86_64/vga/writer.rs`: `VgaWriter::canvas: Option<CanvasBuffer>`
   becomes `Option<Presenter<'static>>` plus `Option<OwnedSurface<KernelOps>>`.
   `draw_to_back`/`track_dirty` toggles become surface selection, the writer's
   own present loop becomes `Presenter::present_owned`, and `cursor.rs`
   accessors follow the same signature change. This is the risky step: it
   needs a QEMU boot test.
3. `hardware/video/framebuffer.rs`: `Framebuffer::canvas` becomes a
   `Presenter`, the three construction sites become `Presenter::from_fb`.
4. `display_scheme.rs` (`/dev/display`): the BGR888→native conversion moves
   from `CanvasBuffer::blit_rect` to `Canvas::convert_from`, which is the bug
   class the old code could not catch.
5. `graphics_adapter.rs`: `HeapScreen`/`Damage` go away with R12 (display
   out of kernel); until then they keep their own model.

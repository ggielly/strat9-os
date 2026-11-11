# fbsurface

Internal framebuffer surface API for strat9. `no_std`, no allocator, no OS
dependency. The kernel instantiates it with the SSE2 backend; the host runs
the same code with the scalar backend.

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

`Canvas` borrows a `&mut [u8]` or points at MMIO (`Canvas::direct`). `View`
borrows a `&[u8]` or points at shared memory, which is how a client buffer or
a wire payload is blitted without an intermediate copy. Neither allocates.
Paged storage (`HeapScreen`) is out of scope: it is the thing R12 removes from
the kernel.

## Kernel adapter

`strat9-kernel::framebuffer::surface` provides:

- `KernelOps`: `PixelOps` over `FramebufferOps`, with `FpuGuard` from every
  drawing call;
- `Presenter`: write-combining fence, `PRESENT_MIN_TICKS` rate limit and
  damage-driven present;
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
| `CanvasBuffer::enable_back_buffer` | caller-owned second `Canvas` |
| `FramebufferOps::blend` (unused) | `Canvas::blend_rect` |
| `PixelFormat` at the pixel API | `Format` |
| raw `u32` colour | `Packed` |

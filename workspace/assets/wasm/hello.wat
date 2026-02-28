(module
  (type $fd_write_t (func (param i32 i32 i32 i32) (result i32)))
  (type $start_t (func))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (type $fd_write_t)))
  (memory 1)
  (export "memory" (memory 0))
  (data (i32.const 8) "hello world!\n")
  (func $_start (type $start_t)
    i32.const 0
    i32.const 8
    i32.store
    i32.const 4
    i32.const 13
    i32.store
    i32.const 1
    i32.const 0
    i32.const 1
    i32.const 20
    call $fd_write
    drop)
  (export "_start" (func $_start))
)

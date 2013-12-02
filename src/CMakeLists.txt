set(src_SRCS
  mxserver.c
  connection_handler.c
  command_handler.c
  queue.c
  device_manager.c
  algorithm_manager.c
  )

add_executable(mxserver ${src_SRCS})
target_link_libraries(mxserver pthread sm)

install(TARGETS mxserver DESTINATION bin)

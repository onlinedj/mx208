set(base_SRCS
  mxserver.c
  connection_handler.c
  command_handler.c
  queue.c
  )

add_executable(mxserver ${base_SRCS})
target_link_libraries(mxserver pthread)

install(TARGETS mxserver DESTINATION bin)

set(src_SRCS
  mxserver.c
  connection_handler.c
  command_handler.c
  queue.c
  )

add_executable(mxserver ${src_SRCS})
target_link_libraries(mxserver pthread)

install(TARGETS mxserver DESTINATION bin)

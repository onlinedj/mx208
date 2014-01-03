set(src_SRCS
  mxserver.c
  connection_handler.c
  commands.c
  command_handler.c
  queue.c
  device_manager.c
  key_manager.c
  data_parser.c
  data_composer.c
  file_manager.c
  )

add_executable(mxserver ${src_SRCS})
target_link_libraries(mxserver pthread sm)

install(TARGETS mxserver DESTINATION bin)

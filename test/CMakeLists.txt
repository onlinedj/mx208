#client interact to server
set(client_SRCS
  client.c
  ../src/data_composer.c
  ../src/data_parser.c
  )

add_executable(client ${client_SRCS})
#target_link_libraries(client pthread)

install(TARGETS client DESTINATION bin)

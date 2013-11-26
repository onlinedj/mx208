#client interact to server
set(client_SRCS
  client.c
  )

add_executable(client ${client_SRCS})
#target_link_libraries(client pthread)

install(TARGETS client DESTINATION bin)

#commands verify the command id themself
set(commands_SRCS
  commands.c
  )

add_executable(commands ${commands_SRCS})

install(TARGETS commands DESTINATION bin)

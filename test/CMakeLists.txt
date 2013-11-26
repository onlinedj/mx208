set(test_SRCS
  client.c
  )

add_executable(client ${test_SRCS})
#target_link_libraries(mxserver pthread)

install(TARGETS client DESTINATION bin)

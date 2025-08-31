! Simple hello world program in Fortran with some complexity for analysis
program hello_world
    implicit none

    ! Variable declarations
    integer :: i, sum_len
    integer :: num_args
    character(len=100) :: arg
    integer, parameter :: global_counter = 42

    ! Print hello message
    print *, "Hello, World from Fortran!"

    ! Get command line arguments
    num_args = command_argument_count()

    ! Calculate sum of argument lengths
    sum_len = 0
    do i = 1, num_args
        call get_command_argument(i, arg)
        sum_len = sum_len + len_trim(arg)
    end do

    ! Print results
    print *, "Number of arguments:", num_args
    print *, "Total argument length:", sum_len
    print *, "Global counter:", global_counter

    ! Call a subroutine
    call print_message("Fortran subroutine called")

contains

    ! Subroutine for additional complexity
    subroutine print_message(msg)
        character(len=*), intent(in) :: msg
        integer, save :: call_count = 0

        call_count = call_count + 1
        print *, msg
        print *, "Subroutine called", call_count, "times"
    end subroutine print_message

end program hello_world
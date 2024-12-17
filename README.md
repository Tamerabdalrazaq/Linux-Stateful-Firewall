A  kernel module imitating a static firewall
Improvements from previous assignment:
  - The kernel does not format the output data to the user-space
## Notes
  - in my machine I needed to modify permissions for accessing devices (bash commands in bash_commands file)
  - Creating a char device using mknod (in bash_commands file), major number is printed on module initialization
  - Entry functions for devices:
    - display, modify for rules
    - reset_store for resetting logs
    - my_read for char dev, reading log


### Resources:
No external recourses.
Used Chat-GPT for documentations and helper functions. 
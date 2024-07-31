# Sputnik
The (un)official sequel to [Voyager](https://github.com/backengineering/Voyager) framework.

Hook chains and signatures were updated to the latest Windows 10 and 11 (22H2).
They might **not** work for other versions.

## Why
This project is meant to be an extension of [SKLib](https://github.com/cutecatsandvirtualmachines/SKLib) and
my [Cheat Driver](https://github.com/cutecatsandvirtualmachines/CheatDriver) project.

Beforehand, an hypervisor engine from SKLib was used, which provided a nice core for most of the interesting functionalities
I have implemented.

Porting this to a bootkit would be cumbersome and waste a lot of time, so I thought it'd be a good idea to just use Microsoft's
work and hijack their hypervisor, as Voyager does.

This way the core shifts deeper into Hyper-v, while the kernel driver acts as a second layer between usermode and the internal core.

### PayLoad
This is the core, entirely based on Voyager, with added pt, ept, identity map, exception handling, etc.

The core has only been tested for AMD as I had no time to work on Intel. Will maybe finish it one day.

### TestLoader
Will automatically test for necessary conditions for load, and attempt automatic load.

### CheatDriver
Port from https://github.com/cutecatsandvirtualmachines/CheatDriver.
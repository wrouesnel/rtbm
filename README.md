# Real Time Bandwidth Monitor

This project is a fork of the original intelligent real-time bandwidth monitor 
project found here <https://code.google.com/p/rtbm/>.

That project has been largely defunct for a while, but implements a very nice
and easy to read interface. Given the relative dearth of similar functionalities
which can be easily dropped onto a Linux router that's not running one of the
standard firewall distributions, I thought I'd pick up the project and adapt it
to suit my needs.

The basic outline will show a 5 minute snapshot of bandwidth usage, updated by
the second but does no long-term logging (there are better tools for that at
the moment). The principle use case is answering that age-old "who's using all 
the internet" question around the house.


#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Kendall's Notation",
    description: "An explanation of Kendall's notation for classifying queueing systems based on arrival processes, service time distributions, number of servers, and system capacity.",
    date: "2025-12-11",
    order: 2,
  ),
)<frontmatter>

= Kendall's Notation

Before starting the investigations of elementary queueing systems let us introduce a notation originated by Kendall to describe a queueing system.

Let us denote a system by

$ A \/ B \/ m \/ K \/ n \/ D, $

where

- $A$: distribution function of the interarrival times,
- $B$: distribution function of the service times,
- $m$: number of servers,
- $K$: capacity of the system, the maximum number of customers in the system including the one being serviced,
- $n$: population size, number of sources of customers,
- $D$: service discipline.

Exponentially distributed random variables are notated by $M$, meaning Markovian or memoryless.

Furthermore, if the population size and the capacity is infinite, the service discipline is FIFO, then they are omitted.

Hence $M/M/1$ denotes a system with Poisson arrivals, exponentially distributed service times and a single server. $M/G/m$ denotes an $m$-server system with Poisson arrivals and generally distributed service times. $M/M/r/K/n$ stands for a system where the customers arrive from a finite-source with $n$ elements where they stay for an exponentially distributed time, the service times are exponentially distributed, the service is carried out according to the request’s arrival by $r$ servers, and the system capacity is $K$.

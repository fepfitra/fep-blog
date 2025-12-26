#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Queueing System Characterization",
    description: "An overview of how to characterize queueing systems in terms of arrival processes, service times, and performance measures.",
    date: "2025-12-11",
    order: 1,
  ),
)<frontmatter>

= Queueing System Characterization

To characterize a queueing system we have to identify the probabilistic properties of the incoming flow of requests, service times and service disciplines. The arrival process can be characterized by the distribution of the interarrival times of the customers, denoted by $A(t)$, that is

$ A(t) = P("interarrival time" < t). $

In queueing theory these interarrival times are usually assumed to be independent and identically distributed random variables. The other random variable is the service time, sometimes it is called service request, work. Its distribution function is denoted by $B(x)$, that is

$ B(x) = P("service time" < x). $

The service times, and interarrival times are commonly supposed to be independent random variables.

The structure of service and service discipline tell us the number of servers, the capacity of the system, that is the maximum number of customers staying in the system including the ones being under service. The service discipline determines the rule according to the next customer is selected. The most commonly used laws are:

- *FIFO* - First In First Out: who comes earlier leaves earlier
- *LIFO* - Last Come First Out: who comes later leaves earlier
- *RS* - Random Service: the customer is selected randomly
- *Priority*

The aim of all investigations in queueing theory is to get the main performance measures of the system which are the probabilistic properties (distribution function, density function, mean, variance) of the following random variables: number of customers in the system, number of waiting customers, utilization of the server/s, response time of a customer, waiting time of a customer, idle time of the server, busy time of a server. Of course, the answers heavily depends on the assumptions concerning the distribution of interarrival times, service times, number of servers, capacity and service discipline. It is quite rare, except for elementary or Markovian systems, that the distributions can be computed. Usually their mean or transforms can be calculated.

== Traffic Intensity and Utilization

For simplicity consider first a single-server system. Let $rho$, called traffic intensity, be defined as

$ rho = ("mean service time") / ("mean interarrival time"). $

Assuming an infinity population system with arrival intensity $lambda$, which is reciprocal of the mean interarrival time, and let the mean service denote by $1/mu$. Then we have

$ rho = "arrival intensity" times "mean service time" = lambda / mu. $

If $rho > 1$ then the systems is overloaded since the requests arrive faster than as the are served. It shows that more server are needed.

Let $chi(A)$ denote the characteristic function of event $A$, that is

$
  chi(A) = cases(
    1\, & "if" A "occurs",
    0\, & "if" A "does not"
  )
$

Furthermore, let $N(t) = 0$ denote the event that at time $T$ the server is idle, that is no customer in the system. Then the utilization of the server during time $T$ is defined by

$ 1/T integral_0^T chi(N(t) != 0) dif t, $

where $T$ is a long interval of time. As $T -> infinity$ we get the utilization of the server denoted by $U_s$ and the following relations holds with probability 1

$ U_s = lim_(T -> infinity) 1/T integral_0^T chi(N(t) != 0) dif t = 1 - P_0 = (E delta) / (E delta + E_i), $

where $P_0$ is the steady-state probability that the server is idle, and $E delta, E_i$ denote the mean busy period, mean idle period of the server, respectively.

This formula is a special case of the relationship valid for continuous-time Markov chains and proved in Tomkó [93].

*Theorem 1.* Let $X(t)$ be an ergodic Markov chain, and $A$ is a subset of its state space. Then with probability 1

$ lim_(T -> infinity) 1/T ( integral_0^T chi(X(t) in A) dif t ) = sum_(i in A) P_i = (m(A)) / (m(A) + m(overline(A))), $

where $m(A)$ and $m(overline(A))$ denote the mean sojourn time of the chain in $A$ and $overline(A)$ during a cycle, respectively. The ergodic (stationary, steady-state) distribution of $X(t)$ is denoted by $P_i$.

== Multi-Server Systems and Performance Measures

In an $m$-server system the mean number of arrivals to a given server during time $T$ is $lambda T\/m$ given that the arrivals are uniformly distributed over the servers. Thus the utilization of a given server is

$ U_s = lambda / (m mu). $

The other important measure of the system is the throughput of the system which is defined as the mean number of requests serviced during a time unit. In an $m$-server system the mean number of completed services is $m rho mu$ and thus

$ "throughput" = m U_s mu. $

However, if we consider now the customers for a tagged customer the waiting and response times are more important than the measures defined above. Let us define by $W_j, T_j$ the waiting, response time of the $j$-th customer, respectively. Clearly the waiting time is the time a customer spends in the queue waiting for service, and response time is the time a customer spends in the system, that is

$ T_j = W_j + S_j, $

where $S_j$ denotes its service time. Of course, $W_j$ and $T_j$ are random variables and their mean, denoted by $overline(W)_j$ and $overline(T)_j$, are appropriate for measuring the efficiency of the system. It is not easy in general to obtain their distribution function.

Other characteristic of the system is the queue length, and the number of customers in the system. Let the random variables $Q(t), N(t)$ denote the number of customers in the queue, in the system at time $t$, respectively. Clearly, in an $m$-server system the queue length is given by

$ Q(t) = max(0, N(t) - m). $

The primary aim is to get their distributions, but it is not always possible, many times we have only their mean values or their generating function.

#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Basic Relations for Birth-Death Processes",
    description: "An exploration of fundamental relationships in birth-death processes, including steady-state distributions and arrival/departure dynamics.",
    date: "2025-12-11",
    order: 3,
  ),
)<frontmatter>

= Basic Relations for Birth-Death Processes

Since birth-death processes play a very important role in modeling elementary queueing systems let us consider some useful relationships for them. Clearly, arrivals mean birth and services mean death.

As we have seen earlier the steady-state distribution for birth-death processes can be obtained in a very nice closed-form, that is

$ P_i = (lambda_0 dots.c lambda_(i-1)) / (mu_1 dots.c mu_i) P_0, quad i = 1, 2, dots.c $ <eq1.1a>
$ P_0^(-1) = 1 + sum_(i=1)^infinity (lambda_0 dots.c lambda_(i-1)) / (mu_1 dots.c mu_i). $ <eq1.1b>

Let us consider the distributions at the moments of arrivals, departures, respectively, because we shall use them later on.

Let $N_a, N_d$ denote the state of the process at the instant of births, deaths, respectively, and let $Pi_k = P(N_a = k), D_k = P(N_d = k), k = 0, 1, 2, dots$ stand for their distributions.
By applying the Bayes's theorem it is easy to see that

$
  Pi_k & = lim_(h -> 0) ((lambda_k h + o(h))P_k) / (sum_(j=0)^infinity (lambda_j h + o(h))P_j) \
       & = (lambda_k P_k) / (sum_(j=0)^infinity lambda_j P_j).
$ <eq1.2>

Similarly

$
  D_k & = lim_(h -> 0) ((mu_(k+1) h + o(h))P_(k+1)) / (sum_(j=1)^infinity (mu_j h + o(h))P_j) \
      & = (mu_(k+1) P_(k+1)) / (sum_(j=1)^infinity mu_j P_j).
$ <eq1.3>

Since $P_(k+1) = lambda_k / mu_(k+1) P_k, k = 0, 1, dots$, thus

$ D_k = (lambda_k P_k) / (sum_(i=0)^infinity lambda_i P_i) = Pi_k, quad k = 0, 1, dots.c $ <eq1.4>

In words, the above relation states that the steady-state distributions at the moments of births and deaths are the same. It should be underlined, that it does not mean that it is equal to the steady-state distribution at a random point as we will see later on.

Further essential observation is that in steady-state the mean birth rate is equal to the mean death rate. This can be seen as follows

$
  lambda = sum_(i=0)^infinity lambda_i P_i = sum_(i=0)^infinity mu_(i+1) P_(i+1) = sum_(k=1)^infinity mu_k P_k = mu
$ <eq1.5>

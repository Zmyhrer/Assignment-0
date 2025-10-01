**Aristocrat Cipher Solver**

A Python tool for solving monoalphabetic aristocrat ciphers using multiple strategies, including pattern analysis, frequency analysis, hill climbing, and a genetic algorithm with quadgram scoring.

**Features**

Cipher Preprocessing: Cleans and normalizes ciphertext for analysis.

Frequency Analysis: Computes letter frequency statistics to guide initial guesses.

Pattern Matching: Matches word patterns to common English words.

Candidate Key Generation: Generates keys randomly, via frequency heuristics, or using pattern locks.

Decoding: Supports decoding ciphertext using a candidate key.

**Scoring:**

Wordlist matching

N-gram scoring (bigrams, trigrams, quadgrams)

Weighted combination scoring

Solver Algorithms:

Hill Climbing / Simulated Annealing: Iteratively refines candidate keys.

Genetic Algorithm: Evolves a population of keys with crossover and mutation.

**Dependencies:**

Python 3.8+

wordfreq

requests

Install dependencies manually if needed:

pip install wordfreq requests

Usage
Hill Climb Solver
from solver import run_solver

ciphertext = """YPLOBGT TOH OSOHHDO PF RHP VDOOS RDPLH RHP LPE DPDDLY SPLRHBG..."""
run_solver(ciphertext)

**What it does:**

Loads a wordlist and common n-grams.

Preprocesses the ciphertext.

Generates candidate keys using multiple strategies.

Performs hill climbing to optimize key based on scoring.

Prints the best plaintext candidate and score.

Genetic Algorithm Solver
from genetic_solver import load_quadgrams, GeneticSolver

quadgram_data = load_quadgrams()
ciphertext = """ZIT LZGFTL GF ZIT IOSS VIOLHTKTR VIOST ZIT VOFR VQL EGXFZOFU RQNL. OF ZIT DQKATZ ZIT WQATK IXDDTR QF GSR ZXFT QFR EIOSRKTF EIQLTR ZIT AOZT QSGFU ZIT SQFT. TCTFOFU YTSS QFR SQFZTKFL WSOFATR SOAT YOKTYSOTL; LZKQFUTKL LIQKTR LZGKOTL XFRTK ZIT TSD. Q LDQSS ESGEA LZKXEA DORFOUIZ QL ROLZQFZ WTSSL KTHSOTR."""
Meaning: The stones on the hill whispered while the wind was counting days. In the market the baker hummed an old tune and children chased the kite along the lane. Evening fell and lanterns blinked like fireflies; strangers shared stories under the elm. A small clock struck midnight as distant bells replied.
solver = GeneticSolver(ciphertext, population_size=500, quadgram_data=quadgram_data)
solver.solve(
    generations=5000,
    elite_percent=0.05,
    base_mutation_rate=0.05,
    stagnation_limit=200,
    tournament_size=4
)


**What it does:**

Initializes a population of candidate keys.

Evaluates each key using quadgram-based fitness scores.

Evolves the population with selection, crossover, and mutation.

Prints the best decoded plaintext along with the key mapping.

Configuration

population_size: Number of candidate keys per generation (genetic algorithm).

generations: Total generations to run the GA solver.

elite_percent: Fraction of top performers retained each generation.

base_mutation_rate: Probability of mutation per key.

stagnation_limit: Number of stagnant generations before increasing mutation.

tournament_size: Size of the tournament for selection in GA.

CACHE_DIR (~/.cache/aristocrat) stores n-gram pickle files to avoid repeated downloads.

**Notes**

Quadgram data is fetched from a public repository. A local fallback is used if the download fails.

Random seed can be set for deterministic results (random.seed(42)).

Ciphertext must be a substitution cipher (uppercase letters A–Z).

**References**

Word frequency list: wordfreq Python package

Gutenberg Project for n-gram generation

Substitution cipher analysis techniques: frequency analysis, pattern matching, and n-gram scoring.

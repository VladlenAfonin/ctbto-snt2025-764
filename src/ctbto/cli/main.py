import sys
from time import time_ns
from types import ModuleType

import numpy
from tqdm import tqdm
from matplotlib import pyplot as plt
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC

import scienceplots


def run_signature(
    input_size: int = 4096,
    hash_function: ModuleType = SHA256,
    n_iter: int = 100,
) -> numpy.float32:
    secret = ECC.generate(curve="p256")
    input = b"0" * input_size
    signer = DSS.new(secret, "fips-186-3")

    times = []
    for _ in tqdm(range(n_iter), leave=False):
        begin = time_ns()

        input_digest = hash_function.new(input)
        _ = signer.sign(input_digest)

        end = time_ns()
        times.append(end - begin)

    return numpy.mean(times)


def run_hmac(
    secret_size: int = 20,
    input_size: int = 4096,
    hash_function: ModuleType = SHA256,
    n_iter: int = 100,
) -> numpy.float32:
    secret = b"0" * secret_size
    input = b"0" * input_size
    clean_hmac = HMAC.new(secret, digestmod=hash_function)

    times = []
    for _ in tqdm(range(n_iter), leave=False):
        working_hmac = clean_hmac.copy()
        begin = time_ns()

        working_hmac.update(input)
        _ = working_hmac.digest()

        end = time_ns()
        times.append(end - begin)

    return numpy.mean(times)


def main() -> int:
    xs = numpy.linspace(0.1, 50.0, 10)
    xs = numpy.int64(xs * 1024 * 1024)
    n_iter = 10

    run_hmac_vec = numpy.vectorize(
        run_hmac,
        excluded=["secret_size", "hash_function", "n_iter"],
    )
    ys_hmac = run_hmac_vec(input_size=xs, n_iter=n_iter) // 1_000_000

    run_signature_vec = numpy.vectorize(
        run_signature,
        excluded=["hash_function", "n_iter"],
    )
    ys_ecdsa = run_signature_vec(input_size=xs, n_iter=n_iter) // 1_000_000

    plt.style.use("science")
    _, ax = plt.subplots()
    ax.plot(xs / 1024 / 1024, ys_hmac, label=r"$\textsf{HMAC}$")
    ax.plot(xs / 1024 / 1024, ys_ecdsa, label=r"$\textsf{ECDSA}$")
    plt.legend()
    plt.show()

    return 0


if __name__ == "__main__":
    result = main()
    sys.exit(result)

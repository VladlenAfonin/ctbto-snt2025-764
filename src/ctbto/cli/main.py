import logging
import logging.config
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


logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {"format": "%(levelname)s:%(name)s:%(funcName)s():%(message)s"}
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "ctbto.cli.main": {"level": "INFO", "handlers": ["stdout"]},
    },
}

logging.config.dictConfig(logging_config)
logger = logging.getLogger(__name__)


def run_ecdsa(
    input_size: int,
    hash_function: ModuleType = SHA256,
    n_iter: int = 100,
) -> numpy.float32:
    times = []
    for _ in tqdm(range(n_iter), leave=False):
        secret = ECC.generate(curve="p256")
        signer = DSS.new(secret, "fips-186-3")
        input = numpy.random.bytes(input_size)

        begin = time_ns()

        input_digest = hash_function.new(input)
        _ = signer.sign(input_digest)

        end = time_ns()
        times.append(end - begin)

    return numpy.mean(times)


def run_hmac(
    input_size: int,
    secret_size: int = 32,
    hash_function: ModuleType = SHA256,
    n_iter: int = 100,
) -> numpy.float32:
    times = []
    for _ in tqdm(range(n_iter), leave=False):
        secret = numpy.random.bytes(secret_size)
        input = numpy.random.bytes(input_size)

        begin = time_ns()

        hmac = HMAC.new(secret, input, digestmod=hash_function)
        _ = hmac.digest()

        end = time_ns()
        times.append(end - begin)

    return numpy.mean(times)


def megabytes_to_bytes(xs: numpy.ndarray) -> numpy.ndarray:
    return (xs * 1024 * 1024).astype(numpy.int64)


def bytes_to_megabytes(xs: numpy.ndarray) -> numpy.ndarray:
    return xs / 1024 / 1024


def main() -> int:
    xs = numpy.linspace(start=0.1, stop=10.0, num=30)
    xs = megabytes_to_bytes(xs)
    print(xs)
    n_iter = 10

    logger.info("begin benchmarking hmac-sha256")
    ys_hmac = []
    for x in tqdm(xs):
        ys_hmac.append(
            run_hmac(x, n_iter=n_iter) // 1_000_000,
        )
    ys_hmac = numpy.array(ys_hmac)
    logger.info("end benchmarking hmac-sha256")

    logger.info("begin benchmarking ecdsa")
    ys_ecdsa = []
    for x in tqdm(xs):
        ys_ecdsa.append(
            run_ecdsa(x, n_iter=n_iter) // 1_000_000,
        )
    ys_ecdsa = numpy.array(ys_ecdsa)
    logger.info("end benchmarking ecdsa")

    xs = bytes_to_megabytes(xs)

    plt.style.use(["science"])
    _, ax = plt.subplots()

    ax.set_xlabel("Input size, MB")
    ax.set_ylabel("Generation time, ms")
    ax.plot(xs, ys_hmac, label=r"$\textsf{HMAC-SHA256}$")
    ax.plot(xs, ys_ecdsa, label=r"$\textsf{ECDSA-SHA256}$")

    plt.legend()
    plt.show()

    return 0


if __name__ == "__main__":
    result = main()
    sys.exit(result)

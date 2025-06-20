import argparse
from dataclasses import dataclass
import logging
import logging.config
import os
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


def bytes_to_kilobytes(xs: numpy.ndarray) -> numpy.ndarray:
    return xs / 1024


def kilobytes_to_bytes(xs: numpy.ndarray) -> numpy.ndarray:
    return (xs * 1024).astype(numpy.int64)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="supporting benchmark program for the CTBTO SnT 2025 conference e-poster #764",
    )

    n_iter_default = 100_000
    parser.add_argument(
        "-n",
        help=f"number of iterations to perform for one measurement. default: {n_iter_default}",
        dest="n_iter",
        action="store",
        metavar="NUMBER",
        default=n_iter_default,
        type=int,
    )

    parser.add_argument(
        "-o",
        "--output",
        help=f"output file name with extension. by default the image is"
        + "displayed after generation in a separate window",
        dest="output_file",
        action="store",
        metavar="FILE",
        default=None,
        type=str,
    )

    parser.add_argument(
        "-s",
        "--save",
        help=f"save generated data into a directory",
        dest="save_dir",
        action="store",
        metavar="DIR",
        default=None,
        type=str,
    )

    parser.add_argument(
        "-l",
        "--load",
        help=f"load generated data from a directory",
        dest="load_dir",
        action="store",
        metavar="DIR",
        default=None,
        type=str,
    )

    return parser.parse_args()


@dataclass(slots=True)
class BenchmarkResults:
    xs: numpy.ndarray
    ys_hmac: numpy.ndarray
    ys_ecdsa: numpy.ndarray


@dataclass(slots=True, init=False)
class BenchmarkResultsPaths:
    root_dir: str
    xs_path: str
    ys_hmac_path: str
    ys_ecdsa_path: str

    def __init__(self, dir) -> None:
        self.root_dir = dir
        self.xs_path = os.path.join(dir, "xs.txt")
        self.ys_hmac_path = os.path.join(dir, "ys_hmac.txt")
        self.ys_ecdsa_path = os.path.join(dir, "ys_ecdsa.txt")

    def save(
        self,
        benchmark_results: BenchmarkResults,
    ) -> None:
        logger.info(f"begin saving data into directory {self.root_dir}")

        numpy.savetxt(self.xs_path, benchmark_results.xs)
        numpy.savetxt(self.ys_hmac_path, benchmark_results.ys_hmac)
        numpy.savetxt(self.ys_ecdsa_path, benchmark_results.ys_ecdsa)

        logger.info(f"end saving data into directory {self.root_dir}")

    def verify(self) -> bool:
        logger.info("verifying directory structure")

        if not (
            os.path.isfile(self.xs_path)
            and os.path.isfile(self.ys_hmac_path)
            and os.path.isfile(self.ys_ecdsa_path)
        ):
            logger.error(f"invalid data inside directory {self.root_dir}")
            return False

        return True

    def load(self) -> BenchmarkResults:
        logger.info(f"begin loading data from directory {self.root_dir}")
        results = BenchmarkResults(
            xs=numpy.loadtxt(self.xs_path),
            ys_hmac=numpy.loadtxt(self.ys_hmac_path),
            ys_ecdsa=numpy.loadtxt(self.ys_ecdsa_path),
        )
        logger.info(f"end loading data from directory {self.root_dir}")

        return results


def run_benchmarks(n_iter) -> BenchmarkResults:
    xs = numpy.linspace(start=1, stop=100, num=100)
    xs = kilobytes_to_bytes(xs)

    logger.info("begin benchmarking hmac-sha256")
    ys_hmac = []
    for x in tqdm(xs):
        ys_hmac.append(
            run_hmac(x, n_iter=n_iter) // 1_000,
        )
    ys_hmac = numpy.array(ys_hmac)
    logger.info("end benchmarking hmac-sha256")

    logger.info("begin benchmarking ecdsa")
    ys_ecdsa = []
    for x in tqdm(xs):
        ys_ecdsa.append(
            run_ecdsa(x, n_iter=n_iter) // 1_000,
        )
    ys_ecdsa = numpy.array(ys_ecdsa)
    logger.info("end benchmarking ecdsa")

    xs = bytes_to_kilobytes(xs)

    return BenchmarkResults(
        xs=xs,
        ys_hmac=ys_hmac,
        ys_ecdsa=ys_ecdsa,
    )


def main() -> int:
    args = parse_args()

    if args.load_dir is None:
        benchmark_results = run_benchmarks(args.n_iter)

        if args.save_dir is not None:
            if not os.path.isdir(args.save_dir):
                os.mkdir(args.save_dir)

            benchmark_paths = BenchmarkResultsPaths(args.save_dir)
            benchmark_paths.save(benchmark_results)
    else:
        if not os.path.isdir(args.load_dir):
            logger.error(f"specified load directory does not exist: {args.load_dir}")
            return 1

        benchmark_paths = BenchmarkResultsPaths(args.load_dir)

        if not benchmark_paths.verify():
            logger.error(f"invalid data inside directory {args.load_dir}")
            return 1

        benchmark_results = benchmark_paths.load()

    logger.info("begin generating image")
    plt.style.use(["science"])
    _, ax = plt.subplots()

    ax.set_xlabel(r"Input size, KB")
    ax.set_ylabel(r"Generation time, $\mu$s")
    ax.plot(
        benchmark_results.xs,
        benchmark_results.ys_hmac,
        label=r"$\textsf{HMAC-SHA256}$",
    )
    ax.plot(
        benchmark_results.xs,
        benchmark_results.ys_ecdsa,
        label=r"$\textsf{ECDSA-SHA256}$",
    )

    plt.legend()
    logger.info("end generating image")

    if args.output_file is None:
        logger.info(f"begin displaying the image")
        plt.show()
        logger.info(f"end displaying the image")
    else:
        logger.info(f"begin saving the image to file {args.output_file}")
        plt.savefig(args.output_file, dpi=300)
        logger.info(f"end saving the image to file {args.output_file}")

    return 0


if __name__ == "__main__":
    result = main()
    sys.exit(result)

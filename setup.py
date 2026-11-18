"""Copy sneak1024-seed.txt next to sneak_n2.py in the wheel.

setuptools py-modules cannot declare adjacent data files, and the cipher
looks up the public demo seed at SEED_PATH next to sneak_n2.py (unchanged).
build_py copies the seed into the build lib root so ``pip install .`` keeps
load_seed() working from site-packages. Metadata lives in pyproject.toml.
"""
from setuptools import setup
from setuptools.command.build_py import build_py
import os

_SEED = "sneak1024-seed.txt"


class BuildPy(build_py):
    def run(self):
        super().run()
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), _SEED)
        if not os.path.isfile(src):
            raise FileNotFoundError("demo seed missing: %s" % src)
        self.copy_file(src, os.path.join(self.build_lib, _SEED), preserve_mode=True)


setup(cmdclass={"build_py": BuildPy})

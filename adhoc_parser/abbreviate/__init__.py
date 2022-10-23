#!/usr/bin/env python

__all__ = ["abbreviate"]
import sys, os, glob, re
from pkg_resources import resource_stream
from .structures import CaseInsensitiveDict


class Abbreviate(object):
    class AbbreviateError(Exception):
        """Base class for abbreviate-specific errors."""

        pass

    class ParseError(AbbreviateError, IOError):
        pass

    def __init__(self):
        self.known = CaseInsensitiveDict()

    def case_match(self, key, val):
        if key == key.lower():
            return val.lower()
        if key == key.upper():
            return val.upper()
        if key == key.title():
            return val.title()
        return val

    def tokenize(self, s):
        return s.split()

    def detokenize(self, t):
        return " ".join(t)

    def basic_known(self, t):
        if t in self.known:
            return self.case_match(t, self.known[t][0][0])
        return t

    def devowel(self, t):
        s = "".join(re.split("[aeiouyAEIOUY]", t))
        v = re.split("[^aeiouyAEIOUY]", t)
        if len(v[0]):
            s = v[0] + s
        if len(v[-1]) and len(v) > 1:
            s = s + v[-1]
        return s

    def _abbreviate(self, t):
        t1 = self.basic_known(t)
        if t1 != t:
            return t1, True

        if len(t) <= 3:
            return t, False

        t2 = self.devowel(t)
        if t2 != t:
            return t2, True

        return t, False

    def abbreviate(
        self,
        string,
        target_len=None,
        len_fn=lambda x: len(x),
        try_harder=False,
        no_matter_what=False,
    ):
        """Shorten a string by abbreviating tokens.
        With no other arguments, well-known abbreviations are applied, but
        nothing more. If a target_len is supplied, some hueristics are applied
        to attempt to automatically shorten words. The try_harder argument will
        apply more aggresive tactics, and no_matter_what will never return a
        string longer than the target (in the extreme case, it will reduce the
        string to an acronym, potentially dropping letters).
        The len_fn argument is a function that takes a single string argument
        and returns a numeric length that is compared to the target_len. By
        default, this function simply counts characters. If no target_len is
        specified, this argument is ignored.
        """
        if target_len is None:
            return " ".join(map(self.basic_known, string.split()))

        if len_fn(string) < target_len:
            return string

        if try_harder or no_matter_what:
            raise NotImplementedError

        # print("Request to abbreviate: {} to len {}".format(string, target_len))

        working = str(string)
        tokens = self.tokenize(working)
        while True:
            lens = map(len_fn, tokens)
            improved = False
            for i in range(len(tokens)):
                t, m = self._abbreviate(tokens[i])
                if m:
                    # print("{} improved to {}".format(tokens[i], t))
                    improved = True
                    tokens[i] = t
                else:
                    continue
                working = self.detokenize(tokens)
                if len_fn(working) < target_len:
                    return self.detokenize(tokens)
            if improved is False:
                break
        # Failed to reach length goal
        return self.detokenize(tokens)


if __name__ == "__main__":
    a = Abbreviate()
    for s in [
        "The quick brown fox jumped over the lazy dog",
        "The Sunday sad bar closed on monday not tuesday this week",
        "Christmas in July is the best holiday",
    ]:
        print(
            "{:3} {}\n{:3} {}\n{:3} {}\n".format(
                len(s),
                s,
                len(a.abbreviate(s)),
                a.abbreviate(s),
                len(a.abbreviate(s, 35)),
                a.abbreviate(s, 35),
            )
        )

:tocdepth: 3

base/bif/strings.bif.zeek
=========================
.. zeek:namespace:: GLOBAL

Definitions of built-in functions related to string processing and
manipulation.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================================ ==========================================================================================================
:zeek:id:`clean`: :zeek:type:`function`                                      Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`count_substr`: :zeek:type:`function`                               Returns the number of times a substring occurs within a string
:zeek:id:`edit`: :zeek:type:`function`                                       Returns an edited version of a string that applies a special
                                                                             "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
:zeek:id:`ends_with`: :zeek:type:`function`                                  Returns whether a string ends with a substring.
:zeek:id:`escape_string`: :zeek:type:`function`                              Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`find_all`: :zeek:type:`function`                                   Finds all occurrences of a pattern in a string.
:zeek:id:`find_all_ordered`: :zeek:type:`function`                           Finds all occurrences of a pattern in a string.
:zeek:id:`find_last`: :zeek:type:`function`                                  Finds the last occurrence of a pattern in a string.
:zeek:id:`find_str`: :zeek:type:`function`                                   Finds a string within another string, starting from the beginning.
:zeek:id:`gsub`: :zeek:type:`function`                                       Substitutes a given replacement string for all occurrences of a pattern
                                                                             in a given string.
:zeek:id:`hexdump`: :zeek:type:`function`                                    Returns a hex dump for given input data.
:zeek:id:`is_alnum`: :zeek:type:`function`                                   Returns whether an entire string is alphanumeric characters
:zeek:id:`is_alpha`: :zeek:type:`function`                                   Returns whether an entire string is alphabetic characters.
:zeek:id:`is_ascii`: :zeek:type:`function`                                   Determines whether a given string contains only ASCII characters.
:zeek:id:`is_num`: :zeek:type:`function`                                     Returns whether an entire string consists only of digits.
:zeek:id:`join_string_vec`: :zeek:type:`function`                            Joins all values in the given vector of strings with a separator placed
                                                                             between each element.
:zeek:id:`levenshtein_distance`: :zeek:type:`function`                       Calculates the Levenshtein distance between the two strings.
:zeek:id:`ljust`: :zeek:type:`function`                                      Returns a left-justified version of the string, padded to a specific length
                                                                             with a specified character.
:zeek:id:`lstrip`: :zeek:type:`function`                                     Removes all combinations of characters in the *chars* argument
                                                                             starting at the beginning of the string until first mismatch.
:zeek:id:`remove_prefix`: :zeek:type:`function`                              Similar to lstrip(), except does the removal repeatedly if the pattern repeats at the start of the string.
:zeek:id:`remove_suffix`: :zeek:type:`function`                              Similar to rstrip(), except does the removal repeatedly if the pattern repeats at the end of the string.
:zeek:id:`reverse`: :zeek:type:`function`                                    Returns a reversed copy of the string
:zeek:id:`rfind_str`: :zeek:type:`function`                                  The same as find(), but returns the highest index matching the substring
                                                                             instead of the smallest.
:zeek:id:`rjust`: :zeek:type:`function`                                      Returns a right-justified version of the string, padded to a specific length
                                                                             with a specified character.
:zeek:id:`rstrip`: :zeek:type:`function`                                     Removes all combinations of characters in the *chars* argument
                                                                             starting at the end of the string until first mismatch.
:zeek:id:`safe_shell_quote`: :zeek:type:`function`                           Takes a string and escapes characters that would allow execution of
                                                                             commands at the shell level.
:zeek:id:`split_string`: :zeek:type:`function`                               Splits a string into an array of strings according to a pattern.
:zeek:id:`split_string1`: :zeek:type:`function`                              Splits a string *once* into a two-element array of strings according to a
                                                                             pattern.
:zeek:id:`split_string_all`: :zeek:type:`function`                           Splits a string into an array of strings according to a pattern.
:zeek:id:`split_string_n`: :zeek:type:`function`                             Splits a string a given number of times into an array of strings according
                                                                             to a pattern.
:zeek:id:`starts_with`: :zeek:type:`function`                                Returns whether a string starts with a substring.
:zeek:id:`str_smith_waterman`: :zeek:type:`function`                         Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
:zeek:id:`str_split`: :zeek:type:`function` :zeek:attr:`&deprecated` = *...* Splits a string into substrings with the help of an index vector of cutting
                                                                             points.
:zeek:id:`str_split_indices`: :zeek:type:`function`                          Splits a string into substrings with the help of an index vector of cutting
                                                                             points.
:zeek:id:`strcmp`: :zeek:type:`function`                                     Lexicographically compares two strings.
:zeek:id:`string_cat`: :zeek:type:`function`                                 Concatenates all arguments into a single string.
:zeek:id:`string_fill`: :zeek:type:`function`                                Generates a string of a given size and fills it with repetitions of a source
                                                                             string.
:zeek:id:`string_to_ascii_hex`: :zeek:type:`function`                        Returns an ASCII hexadecimal representation of a string.
:zeek:id:`strip`: :zeek:type:`function`                                      Strips whitespace at both ends of a string.
:zeek:id:`strstr`: :zeek:type:`function`                                     Locates the first occurrence of one string in another.
:zeek:id:`sub`: :zeek:type:`function`                                        Substitutes a given replacement string for the first occurrence of a pattern
                                                                             in a given string.
:zeek:id:`sub_bytes`: :zeek:type:`function`                                  Get a substring from a string, given a starting position and length.
:zeek:id:`subst_string`: :zeek:type:`function`                               Substitutes each (non-overlapping) appearance of a string in another.
:zeek:id:`swap_case`: :zeek:type:`function`                                  Swaps the case of every alphabetic character in a string.
:zeek:id:`to_lower`: :zeek:type:`function`                                   Replaces all uppercase letters in a string with their lowercase counterpart.
:zeek:id:`to_string_literal`: :zeek:type:`function`                          Replaces non-printable characters in a string with escaped sequences.
:zeek:id:`to_title`: :zeek:type:`function`                                   Converts a string to Title Case.
:zeek:id:`to_upper`: :zeek:type:`function`                                   Replaces all lowercase letters in a string with their uppercase counterpart.
:zeek:id:`zfill`: :zeek:type:`function`                                      Returns a copy of a string filled on the left side with zeroes.
============================================================================ ==========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: clean

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
   
   If the string does not yet have a trailing NUL, one is added internally.
   
   In contrast to :zeek:id:`escape_string`, this encoding is *not* fully reversible.`
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: to_string_literal escape_string

.. zeek:id:: count_substr

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`count`

   Returns the number of times a substring occurs within a string
   

   :str: The string to search in.

   :substr: The string to search for.
   

   :returns: The number of times the substring occurred.
   

.. zeek:id:: edit

   :Type: :zeek:type:`function` (arg_s: :zeek:type:`string`, arg_edit_char: :zeek:type:`string`) : :zeek:type:`string`

   Returns an edited version of a string that applies a special
   "backspace character" (usually ``\x08`` for backspace or ``\x7f`` for DEL).
   For example, ``edit("hello there", "e")`` returns ``"llo t"``.
   

   :arg_s: The string to edit.
   

   :arg_edit_char: A string of exactly one character that represents the
                  "backspace character". If it is longer than one character Zeek
                  generates a run-time error and uses the first character in
                  the string.
   

   :returns: An edited version of *arg_s* where *arg_edit_char* triggers the
            deletion of the last character.
   
   .. zeek:see:: clean
                to_string_literal
                escape_string
                strip

.. zeek:id:: ends_with

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string ends with a substring.
   

.. zeek:id:: escape_string

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
   
   In contrast to :zeek:id:`clean`, this encoding is fully reversible.`
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: clean to_string_literal

.. zeek:id:: find_all

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_set`

   Finds all occurrences of a pattern in a string.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: The set of strings in *str* that match *re*, or the empty set.
   
   .. zeek:see: find_all_ordered find_last strstr

.. zeek:id:: find_all_ordered

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Finds all occurrences of a pattern in a string.  The order in which
   occurrences are found is preverved and the return value may contain
   duplicate elements.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: All strings in *str* that match *re*, or an empty vector.
   
   .. zeek:see: find_all find_last strstr

.. zeek:id:: find_last

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string`

   Finds the last occurrence of a pattern in a string. This function returns
   the match that starts at the largest index in the string, which is not
   necessarily the longest match.  For example, a pattern of ``/.*/`` will
   return the final character in the string.
   

   :str: The string to inspect.
   

   :re: The pattern to look for in *str*.
   

   :returns: The last string in *str* that matches *re*, or the empty string.
   
   .. zeek:see: find_all find_all_ordered strstr

.. zeek:id:: find_str

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`, start: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`, end: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`) : :zeek:type:`int`

   Finds a string within another string, starting from the beginning. This works
   by taking a substring within the provided indexes and searching for the sub
   argument. This means that ranges shorter than the string in the sub argument
   will always return a failure.
   

   :str: The string to search in.

   :substr: The string to search for.

   :start: An optional position for the start of the substring.

   :end: An optional position for the end of the substring. A value less than
        zero (such as the default -1) means a search until the end of the
        string.
   

   :returns: The position of the substring. Returns -1 if the string wasn't
            found. Prints an error if the starting position is after the ending
            position.

.. zeek:id:: gsub

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, repl: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes a given replacement string for all occurrences of a pattern
   in a given string.
   

   :str: The string to perform the substitution in.
   

   :re: The pattern being replaced with *repl*.
   

   :repl: The string that replaces *re*.
   

   :returns: A copy of *str* with all occurrences of *re* replaced with *repl*.
   
   .. zeek:see:: sub subst_string

.. zeek:id:: hexdump

   :Type: :zeek:type:`function` (data_str: :zeek:type:`string`) : :zeek:type:`string`

   Returns a hex dump for given input data. The hex dump renders 16 bytes per
   line, with hex on the left and ASCII (where printable)
   on the right.
   

   :data_str: The string to dump in hex format.
   

   :returns: The hex dump of the given string.
   
   .. zeek:see:: string_to_ascii_hex bytestring_to_hexstr
   
   .. note:: Based on Netdude's hex editor code.
   

.. zeek:id:: is_alnum

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether an entire string is alphanumeric characters
   

.. zeek:id:: is_alpha

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether an entire string is alphabetic characters.
   

.. zeek:id:: is_ascii

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Determines whether a given string contains only ASCII characters.
   

   :str: The string to examine.
   

   :returns: False if any byte value of *str* is greater than 127, and true
            otherwise.
   
   .. zeek:see:: to_upper to_lower

.. zeek:id:: is_num

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether an entire string consists only of digits.
   

.. zeek:id:: join_string_vec

   :Type: :zeek:type:`function` (vec: :zeek:type:`string_vec`, sep: :zeek:type:`string`) : :zeek:type:`string`

   Joins all values in the given vector of strings with a separator placed
   between each element.
   

   :sep: The separator to place between each element.
   

   :vec: The :zeek:type:`string_vec` (``vector of string``).
   

   :returns: The concatenation of all elements in *vec*, with *sep* placed
            between each element.
   
   .. zeek:see:: cat cat_sep string_cat
                fmt

.. zeek:id:: levenshtein_distance

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`) : :zeek:type:`count`

   Calculates the Levenshtein distance between the two strings. See `Wikipedia
   <http://en.wikipedia.org/wiki/Levenshtein_distance>`__ for more information.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :returns: The Levenshtein distance of two strings as a count.
   

.. zeek:id:: ljust

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, width: :zeek:type:`count`, fill: :zeek:type:`string` :zeek:attr:`&default` = ``" "`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Returns a left-justified version of the string, padded to a specific length
   with a specified character.
   

   :str: The string to left-justify.

   :count: The length of the returned string. If this value is less than or
          equal to the length of str, a copy of str is returned.

   :fill: The character used to fill in any extra characters in the resulting
         string. If a string longer than one character is passed, an error is
         reported. This defaults to the space character.
   

   :returns: A left-justified version of a string, padded with characters to a
            specific length.
   

.. zeek:id:: lstrip

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, chars: :zeek:type:`string` :zeek:attr:`&default` = ``" \x09\x0a\x0d\x0b\x0c"`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Removes all combinations of characters in the *chars* argument
   starting at the beginning of the string until first mismatch.
   

   :str: The string to strip characters from.
   

   :chars: A string consisting of the characters to be removed.
          Defaults to all whitespace characters.
   

   :returns: A copy of *str* with the characters in *chars* removed from
            the beginning.
   
   .. zeek:see:: sub gsub strip rstrip

.. zeek:id:: remove_prefix

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`string`

   Similar to lstrip(), except does the removal repeatedly if the pattern repeats at the start of the string.

.. zeek:id:: remove_suffix

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`string`

   Similar to rstrip(), except does the removal repeatedly if the pattern repeats at the end of the string.

.. zeek:id:: reverse

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Returns a reversed copy of the string
   

   :str: The string to reverse.
   

   :returns: A reversed copy of *str*
   

.. zeek:id:: rfind_str

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`, start: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`, end: :zeek:type:`int` :zeek:attr:`&default` = ``-1`` :zeek:attr:`&optional`) : :zeek:type:`int`

   The same as find(), but returns the highest index matching the substring
   instead of the smallest.
   

   :str: The string to search in.

   :substr: The string to search for.

   :start: An optional position for the start of the substring.

   :end: An optional position for the end of the substring. A value less than
        zero (such as the default -1) means a search from the end of the string.
   

   :returns: The position of the substring. Returns -1 if the string wasn't
            found. Prints an error if the starting position is after the ending
            position.

.. zeek:id:: rjust

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, width: :zeek:type:`count`, fill: :zeek:type:`string` :zeek:attr:`&default` = ``" "`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Returns a right-justified version of the string, padded to a specific length
   with a specified character.
   

   :str: The string to right-justify.

   :count: The length of the returned string. If this value is less than or
          equal to the length of str, a copy of str is returned.

   :fill: The character used to fill in any extra characters in the resulting
         string. If a string longer than one character is passed, an error is
         reported. This defaults to the space character.
   

   :returns: A right-justified version of a string, padded with characters to a
            specific length.
   

.. zeek:id:: rstrip

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, chars: :zeek:type:`string` :zeek:attr:`&default` = ``" \x09\x0a\x0d\x0b\x0c"`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Removes all combinations of characters in the *chars* argument
   starting at the end of the string until first mismatch.
   

   :str: The string to strip characters from.
   

   :chars: A string consisting of the characters to be removed.
          Defaults to all whitespace characters.
   

   :returns: A copy of *str* with the characters in *chars* removed from
            the end.
   
   .. zeek:see:: sub gsub strip lstrip

.. zeek:id:: safe_shell_quote

   :Type: :zeek:type:`function` (source: :zeek:type:`string`) : :zeek:type:`string`

   Takes a string and escapes characters that would allow execution of
   commands at the shell level. Must be used before including strings in
   :zeek:id:`system` or similar calls.
   

   :source: The string to escape.
   

   :returns: A shell-escaped version of *source*.  Specifically, this
            backslash-escapes characters whose literal value is not otherwise
            preserved by enclosure in double-quotes (dollar-sign, backquote,
            backslash, and double-quote itself), and then encloses that
            backslash-escaped string in double-quotes to ultimately preserve
            the literal value of all input characters.
   
   .. zeek:see:: system safe_shell_quote

.. zeek:id:: split_string

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string into an array of strings according to a pattern.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each element corresponds to a substring
            in *str* separated by *re*.
   
   .. zeek:see:: split_string1 split_string_all split_string_n str_split
   

.. zeek:id:: split_string1

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string *once* into a two-element array of strings according to a
   pattern. This function is the same as :zeek:id:`split_string`, but *str* is
   only split once (if possible) at the earliest position and an array of two
   strings is returned.
   

   :str: The string to split.
   

   :re: The pattern describing the separator to split *str* in two pieces.
   

   :returns: An array of strings with two elements in which the first represents
            the substring in *str* up to the first occurence of *re*, and the
            second everything after *re*. An array of one string is returned
            when *s* cannot be split.
   
   .. zeek:see:: split_string split_string_all split_string_n str_split

.. zeek:id:: split_string_all

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`) : :zeek:type:`string_vec`

   Splits a string into an array of strings according to a pattern. This
   function is the same as :zeek:id:`split_string`, except that the separators
   are returned as well. For example, ``split_string_all("a-b--cd", /(\-)+/)``
   returns ``{"a", "-", "b", "--", "cd"}``: odd-indexed elements do match the
   pattern and even-indexed ones do not.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :returns: An array of strings where each two successive elements correspond
            to a substring in *str* of the part not matching *re* (even-indexed)
            and the part that matches *re* (odd-indexed).
   
   .. zeek:see:: split_string split_string1 split_string_n str_split

.. zeek:id:: split_string_n

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, incl_sep: :zeek:type:`bool`, max_num_sep: :zeek:type:`count`) : :zeek:type:`string_vec`

   Splits a string a given number of times into an array of strings according
   to a pattern. This function is similar to :zeek:id:`split_string1` and
   :zeek:id:`split_string_all`, but with customizable behavior with respect to
   including separators in the result and the number of times to split.
   

   :str: The string to split.
   

   :re: The pattern describing the element separator in *str*.
   

   :incl_sep: A flag indicating whether to include the separator matches in the
             result (as in :zeek:id:`split_string_all`).
   

   :max_num_sep: The number of times to split *str*.
   

   :returns: An array of strings where, if *incl_sep* is true, each two
            successive elements correspond to a substring in *str* of the part
            not matching *re* (even-indexed) and the part that matches *re*
            (odd-indexed).
   
   .. zeek:see:: split_string split_string1 split_string_all str_split

.. zeek:id:: starts_with

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, sub: :zeek:type:`string`) : :zeek:type:`bool`

   Returns whether a string starts with a substring.
   

.. zeek:id:: str_smith_waterman

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`, params: :zeek:type:`sw_params`) : :zeek:type:`sw_substring_vec`

   Uses the Smith-Waterman algorithm to find similar/overlapping substrings.
   See `Wikipedia <http://en.wikipedia.org/wiki/Smith%E2%80%93Waterman_algorithm>`__.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :params: Parameters for the Smith-Waterman algorithm.
   

   :returns: The result of the Smith-Waterman algorithm calculation.

.. zeek:id:: str_split

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, idx: :zeek:type:`index_vec`) : :zeek:type:`string_vec`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v4.1. Use str_split_indices."*

   Splits a string into substrings with the help of an index vector of cutting
   points.
   

   :s: The string to split.
   

   :idx: The index vector (``vector of count``) with the cutting points.
   

   :returns: A one-indexed vector of strings.
   
   .. zeek:see:: split_string split_string1 split_string_all split_string_n

.. zeek:id:: str_split_indices

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, idx: :zeek:type:`index_vec`) : :zeek:type:`string_vec`

   Splits a string into substrings with the help of an index vector of cutting
   points. This differs from str_split() in that it does not return an empty element
   at the beginning of the result.
   

   :s: The string to split.
   

   :idx: The index vector (``vector of count``) with the cutting points
   

   :returns: A zero-indexed vector of strings.
   
   .. zeek:see:: split_string split_string1 split_string_all split_string_n

.. zeek:id:: strcmp

   :Type: :zeek:type:`function` (s1: :zeek:type:`string`, s2: :zeek:type:`string`) : :zeek:type:`int`

   Lexicographically compares two strings.
   

   :s1: The first string.
   

   :s2: The second string.
   

   :returns: An integer greater than, equal to, or less than 0 according as
            *s1* is greater than, equal to, or less than *s2*.

.. zeek:id:: string_cat

   :Type: :zeek:type:`function` (...) : :zeek:type:`string`

   Concatenates all arguments into a single string. The function takes a
   variable number of arguments of type string and stitches them together.
   

   :returns: The concatenation of all (string) arguments.
   
   .. zeek:see:: cat cat_sep
                fmt
                join_string_vec

.. zeek:id:: string_fill

   :Type: :zeek:type:`function` (len: :zeek:type:`int`, source: :zeek:type:`string`) : :zeek:type:`string`

   Generates a string of a given size and fills it with repetitions of a source
   string.
   

   :len: The length of the output string.
   

   :source: The string to concatenate repeatedly until *len* has been reached.
   

   :returns: A string of length *len* filled with *source*.

.. zeek:id:: string_to_ascii_hex

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`string`

   Returns an ASCII hexadecimal representation of a string.
   

   :s: The string to convert to hex.
   

   :returns: A copy of *s* where each byte is replaced with the corresponding
            hex nibble.

.. zeek:id:: strip

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Strips whitespace at both ends of a string.
   

   :str: The string to strip the whitespace from.
   

   :returns: A copy of *str* with leading and trailing whitespace removed.
   
   .. zeek:see:: sub gsub lstrip rstrip

.. zeek:id:: strstr

   :Type: :zeek:type:`function` (big: :zeek:type:`string`, little: :zeek:type:`string`) : :zeek:type:`count`

   Locates the first occurrence of one string in another.
   

   :big: The string to look in.
   

   :little: The (smaller) string to find inside *big*.
   

   :returns: The location of *little* in *big*, or 0 if *little* is not found in
            *big*.
   
   .. zeek:see:: find_all find_last

.. zeek:id:: sub

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, re: :zeek:type:`pattern`, repl: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes a given replacement string for the first occurrence of a pattern
   in a given string.
   

   :str: The string to perform the substitution in.
   

   :re: The pattern being replaced with *repl*.
   

   :repl: The string that replaces *re*.
   

   :returns: A copy of *str* with the first occurence of *re* replaced with
            *repl*.
   
   .. zeek:see:: gsub subst_string

.. zeek:id:: sub_bytes

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, start: :zeek:type:`count`, n: :zeek:type:`int`) : :zeek:type:`string`

   Get a substring from a string, given a starting position and length.
   

   :s: The string to obtain a substring from.
   

   :start: The starting position of the substring in *s*, where 1 is the first
          character. As a special case, 0 also represents the first character.
   

   :n: The number of characters to extract, beginning at *start*.
   

   :returns: A substring of *s* of length *n* from position *start*.

.. zeek:id:: subst_string

   :Type: :zeek:type:`function` (s: :zeek:type:`string`, from: :zeek:type:`string`, to: :zeek:type:`string`) : :zeek:type:`string`

   Substitutes each (non-overlapping) appearance of a string in another.
   

   :s: The string in which to perform the substitution.
   

   :from: The string to look for which is replaced with *to*.
   

   :to: The string that replaces all occurrences of *from* in *s*.
   

   :returns: A copy of *s* where each occurrence of *from* is replaced with *to*.
   
   .. zeek:see:: sub gsub

.. zeek:id:: swap_case

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Swaps the case of every alphabetic character in a string. For example, the string "aBc" be returned as "AbC".
   

   :str: The string to swap cases in.
   

   :returns: A copy of the str with the case of each character swapped.
   

.. zeek:id:: to_lower

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces all uppercase letters in a string with their lowercase counterpart.
   

   :str: The string to convert to lowercase letters.
   

   :returns: A copy of the given string with the uppercase letters (as indicated
            by ``isascii`` and ``isupper``) folded to lowercase
            (via ``tolower``).
   
   .. zeek:see:: to_upper is_ascii

.. zeek:id:: to_string_literal

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces non-printable characters in a string with escaped sequences. The
   mappings are:
   
       - values not in *[32, 126]* to ``\xXX``
       - ``\`` to ``\\``
       - ``'`` and ``""`` to ``\'`` and ``\"``, respectively.
   

   :str: The string to escape.
   

   :returns: The escaped string.
   
   .. zeek:see:: clean escape_string

.. zeek:id:: to_title

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Converts a string to Title Case. This changes the first character of each sequence of non-space characters
   in the string to be capitalized. See https://docs.python.org/2/library/stdtypes.html#str.title for more info.
   

   :str: The string to convert.
   

   :returns: A title-cased version of the string.
   

.. zeek:id:: to_upper

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`string`

   Replaces all lowercase letters in a string with their uppercase counterpart.
   

   :str: The string to convert to uppercase letters.
   

   :returns: A copy of the given string with the lowercase letters (as indicated
            by ``isascii`` and ``islower``) folded to uppercase
            (via ``toupper``).
   
   .. zeek:see:: to_lower is_ascii

.. zeek:id:: zfill

   :Type: :zeek:type:`function` (str: :zeek:type:`string`, width: :zeek:type:`count`) : :zeek:type:`string`

   Returns a copy of a string filled on the left side with zeroes. This is effectively rjust(str, width, "0").



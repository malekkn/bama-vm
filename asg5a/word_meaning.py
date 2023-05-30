
#!/usr/bin/env python3

from os import popen
import random

ALLOWED_CHARS = 'A1C2E4H5K6M7P8R9UVWXYZ*~^&/:,;-@'
WORD_SIZE = 16

# word has meaning  8:&XX9-CW*4Y@EW@
# Meaning of 8:&XX9-CW*4Y@EW@: "00200000000000".
# word has meaning  V,EK1-ZZA*:A&,8H
# Meaning of V,EK1-ZZA*:A&,8H: "00002000000000".


# word has meaning  @W,&@^WUPX@MW696
# Meaning of @W,&@^WUPX@MW696: "f5a47642894248"

def main():
    while (True):
        seen_words = []
        # create a random word from allowed chars and print it of size 16
        word = ''.join(random.choice(ALLOWED_CHARS) for i in range(WORD_SIZE))

        if word in seen_words:
            continue

        # run oracle binary with the word
        # get exit status of the oracle
        status = popen('./oracle "' + word +'"').read()

        # if the oracle exited with 0, the word has a meaning
        if "Requested word has no meaning" in status:
            seen_words.append(word)
            continue
        # if "00000000000000" in status:
        #     seen_words.append(word)
            # continue
        seen_words.append(word)
        print("word has meaning ", word)
        print(status)


if __name__ == '__main__':
    main()


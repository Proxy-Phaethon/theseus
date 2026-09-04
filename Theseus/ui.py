# animations ehe

import curses


def initialize():
    return curses.wrapper(run)


def run(stdscr):
    stdscr.clear()
    stdscr.border()

    height, width = stdscr.getmaxyx()

    title = " THESEUS "
    stdscr.addstr(0, (width - len(title)) // 2, title)

    stdscr.refresh()

    return stdscr
#pragma once

#include <Windows.h>

void inline pclr(unsigned short attributes) {
    static HANDLE hConsole = NULL;
    if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, attributes);
}

#define B_YELLOW	(FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY)
#define B_RED		(FOREGROUND_RED | FOREGROUND_INTENSITY)
#define B_GREEN		(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define B_BLUE		(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define B_WHITE		(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)

#define YELLOW	(FOREGROUND_GREEN)
#define RED		(FOREGROUND_RED)
#define GREEN	(FOREGROUND_GREEN)
#define BLUE	(FOREGROUND_BLUE)
#define WHITE	(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

#define $BY ); pclr(B_YELLOW); printf(
#define $BR ); pclr(B_RED); printf(
#define $BG ); pclr(B_GREEN); printf(
#define $BB ); pclr(B_BLUE); printf(
#define $BW ); pclr(B_WHITE); printf(

#define $Y ); pclr(YELLOW); printf(
#define $R ); pclr(RED); printf(
#define $G ); pclr(GREEN); printf(
#define $B ); pclr(BLUE); printf(
#define $W ); pclr(WHITE); printf(

#define $fill(...) , __VA_ARGS__); printf(
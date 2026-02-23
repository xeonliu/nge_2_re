#include "stdbool.h"

#define dword_8A65C08 (*(int*)0x8A65C08)

int sub_881AA48()
{
  int v1; // $s0
  int v2; // $s2
  bool v3; // $s1
  int v4; // $s2
  int v5; // $s1
  int v6; // $s0
  int v7; // $hi

  if ( !sub_881A008("SKIP_TITLE") && !sub_881A008("SKIP_LOGO") )
  {
    if ( sub_88077B8() )
    {
      sub_88077E8();
      do
        sub_887233C();
      while ( sub_88077B8() );
    }
    else
    {
      sub_88074C8(0, 0);
      do
      {
        sub_8807588();
        sub_887233C();
      }
      while ( sub_88077B8() );
    }
    sub_8807524();
    v1 = sub_8819B54(0);
    v2 = sub_881ABCC("alfa", 120, 1);
    sub_8819B54(v1);
    v3 = v2 == 0;
    v4 = sub_8819B54(0);
    sub_881ABCC("10th", 120, v3);
    sub_8819B54(v4);
    v5 = 29;
    v6 = 7650;
    v7 = -3570;
    do
    {
      --v5;
      sub_88070A0(((v7 + v6) >> 4) - (v6 >> 31));
      v6 -= 255;
      sub_887233C();
      v7 = (unsigned __int64)(-2004318071LL * v6) >> 32;
    }
    while ( v5 >= 0 );
    if ( !sub_881A008("SKIP_MOVIE") )
    {
      sub_8806958("movie/MASAYUKI.pmf");
      sub_887233C();
    }
  }
  return 0;
}
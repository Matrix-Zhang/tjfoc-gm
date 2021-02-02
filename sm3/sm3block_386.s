#include "textflag.h" 


#define y0 DX
#define y1 DI
#define y2 CX

// X xor Y xor Z
#define ff0(a, b, c) \
    XORL    a,  b; XORL    b,  c

#define gg0(a, b, c)        \
    XORL    a,  b; XORL    b,  c

#define gg1(a, b, c)        \
    ANDL    a,      b;      \
    NOTL    a;              \
    ANDL    a,      c;      \
    ORL     b,      c


#define p0(a)               \
    MOVL    a,      y0;     \
    ROLL    $9,    y0;     \
    XORL    a,      y0;     \
    ROLL    $17,    a;      \
    XORL    y0,     a

#define p1(a)               \
    MOVL    a,      y0;     \
    ROLL    $15,    y0;     \
    XORL    a,      y0;     \
    ROLL    $23,    a;      \
    XORL    y0,     a

#define WMSGFill(index)      \
    MOVL    ((index)*4)(SI), AX; \
    BSWAPL  AX;                 \
    MOVL    AX,((index)*4)(SP)

#define WMSGHandle(index)       \
    MOVL    ((index-16)*4)(SP),   AX;     \
    XORL    ((index-9)*4)(SP),     AX;      \
    MOVL    ((index-3)*4)(SP),      CX;     \
    ROLL    $15,        CX;             \
    XORL    CX,         AX;             \
    p1(AX);                             \
    MOVL    ((index-13)*4)(SP),     CX; \
    ROLL    $7,     CX;                 \
    XORL    CX,         AX;             \
    XORL    ((index-6)*4)(SP),      AX; \
    MOVL    AX,     ((index)*4)(SP)

#define WMSGHandle2(index)          \
    MOVL    ((index)*4)(SP),        CX; \
    XORL    ((index+4)*4)(SP),      CX; \
    MOVL    CX,     ((index+68)*4)(SP)

#define SM3ROUND0(index)       \
    MOVL    ((132+0)*4)(SP),    AX;     \ // A
    ROLL    $12,    AX;     \   // A<<<12
    MOVL    AX,     BX;     \ 
    ADDL    ((132+4)*4)(SP),    AX  \ // A+E
    MOVL    $0x79cc4519,     y0;     \   
    MOVL    $index,    CX;     \
    ANDL    $31,        CX;     \
    ROLL    CX,    y0;  \       //Tj <<< (j mod 32)
    ADDL    y0,     AX; \
    ROLL    $7,     AX; \       // AX = SS1
    XORL    AX,     BX; \       // BX = SS2
    MOVL    ((132+0)*4)(SP),    y0;     \   //A
    MOVL    ((132+1)*4)(SP),    y1;     \   //B
    MOVL    ((132+2)*4)(SP),    y2;     \   //C
    ff0(y0, y1,y2);     \
    ADDL    ((132+3)*4)(SP),    y2;     \   // FF(A,B,C)+D
    ADDL    y2, BX;     \                   // FF(A,B,C)+D+SS2
    ADDL    ((68+index)*4)(SP), BX;     \ // BX = TT1
    MOVL    ((132+4)*4)(SP),    y0;     \   //E
    MOVL    ((132+5)*4)(SP),    y1;     \   //F
    MOVL    ((132+6)*4)(SP),    y2;     \   //G
    gg0(y0, y1, y2);        \
    ADDL    ((132+7)*4)(SP),    y2;     \  // GG+H
    ADDL    y2, AX;     \ //GG + H + SS1
    ADDL    ((index)*4)(SP),    AX;     \ //AX = TT2
    MOVL    ((132+2)*4)(SP),    y0;     \   
    MOVL    y0,    ((132+3)*4)(SP);     \ // D = C
    MOVL    ((132+1)*4)(SP),    y0;     \ 
    ROLL    $9,     y0;                 \
    MOVL    y0,      ((132+2)*4)(SP);   \   // C=B<<<9
    MOVL    ((132+0)*4)(SP),    y0;     \
    MOVL    y0,     ((132+1)*4)(SP);    \ // B=A
    MOVL    BX,      ((132+0)*4)(SP);   \ // A=TT1
    MOVL    ((132+6)*4)(SP),    y0;     \
    MOVL    y0,     ((132+7)*4)(SP);    \ // H=G
    MOVL    ((132+5)*4)(SP),    y0;     \   //F
    ROLL    $19,    y0;                 \
    MOVL    y0,     ((132+6)*4)(SP);    \   // G=F<<<19
    MOVL    ((132+4)*4)(SP),    y0;     \
    MOVL    y0,      ((132+5)*4)(SP);   \   // F=E
    p0(AX);                             \
    MOVL    AX, ((132+4)*4)(SP)         // E=P0(TT2)

#define SM3ROUND1(index)       \
    MOVL    ((132+0)*4)(SP),    AX;     \ // A
    ROLL    $12,    AX;     \   // A<<<12
    MOVL    AX,     BX;     \ 
    ADDL    ((132+4)*4)(SP),    AX  \ // A+E
    MOVL    $0x7a879d8a,     y0;     \   
    MOVL    $index,    CX;     \
    ANDL    $31,        CX;     \
    ROLL    CX,    y0;  \       //Tj <<< (j mod 32)
    ADDL    y0,     AX; \
    ROLL    $7,     AX; \       // AX = SS1
    XORL    AX,     BX; \       // BX = SS2
    MOVL    ((132+0)*4)(SP),    y0;     \   //A
    MOVL    ((132+1)*4)(SP),    y1;     \   //B
    MOVL    ((132+2)*4)(SP),    y2;     \   //C
    ANDL    y0, y1;                     \   // X and Y
    ANDL    y2, y0; ORL     y0, y1;     \   // (X and Y) OR (X and Z)
    MOVL    ((132+1)*4)(SP),    y0;     \   //B          
    ANDL    y0, y2; ORL y1, y2;         \
    ADDL    ((132+3)*4)(SP),    y2;     \   // FF(A,B,C)+D
    ADDL    y2, BX;     \                   // FF(A,B,C)+D+SS2
    ADDL    ((68+index)*4)(SP), BX;     \ // BX = TT1
    MOVL    ((132+4)*4)(SP),    y0;     \   //E
    MOVL    ((132+5)*4)(SP),    y1;     \   //F
    MOVL    ((132+6)*4)(SP),    y2;     \   //G
    gg1(y0, y1, y2);        \
    ADDL    ((132+7)*4)(SP),    y2;     \  // GG+H
    ADDL    y2, AX;     \ //GG + H + SS1
    ADDL    ((index)*4)(SP),    AX;     \ //AX = TT2
    MOVL    ((132+2)*4)(SP),    y0;     \   
    MOVL    y0,    ((132+3)*4)(SP);     \ // D = C
    MOVL    ((132+1)*4)(SP),    y0;     \ 
    ROLL    $9,     y0;                 \
    MOVL    y0,      ((132+2)*4)(SP);   \   // C=B<<<9
    MOVL    ((132+0)*4)(SP),    y0;     \
    MOVL    y0,     ((132+1)*4)(SP);    \ // B=A
    MOVL    BX,      ((132+0)*4)(SP);   \ // A=TT1
    MOVL    ((132+6)*4)(SP),    y0;     \
    MOVL    y0,     ((132+7)*4)(SP);    \ // H=G
    MOVL    ((132+5)*4)(SP),    y0;     \   //F
    ROLL    $19,    y0;                 \
    MOVL    y0,     ((132+6)*4)(SP);    \   // G=F<<<19
    MOVL    ((132+4)*4)(SP),    y0;     \
    MOVL    y0,      ((132+5)*4)(SP);   \   // F=E
    p0(AX);                             \
    MOVL    AX, ((132+4)*4)(SP)         // E=P0(TT2)

TEXT ·block(SB), NOSPLIT, $564-24
    MOVL	b_base+4(FP), SI
	MOVL	b_len+8(FP), DX
	SHRL	$6, DX
	SHLL	$6, DX

    LEAL	(SI)(DX*1), DI
	MOVL	DI, 560(SP)
	CMPL	SI, DI
	JEQ	end

loop:
    MOVL    dig+0(FP), DI
    MOVL    0(DI),  AX
    MOVL    AX,    (132*4)(SP)  // a=H0
    MOVL    4(DI),  AX
    MOVL    AX,    ((132+1)*4)(SP)  // b=H1
    MOVL    8(DI),  AX
    MOVL    AX,    ((132+2)*4)(SP)  // c=H2
    MOVL    12(DI),  AX
    MOVL    AX,    ((132+3)*4)(SP)  // d = H3
    MOVL    16(DI),  AX
    MOVL    AX,    ((132+4)*4)(SP)  // e = H4
    MOVL    20(DI),  AX
    MOVL    AX,    ((132+5)*4)(SP)  // f = H5
    MOVL    24(DI),  AX
    MOVL    AX,    ((132+6)*4)(SP)  // g = H6
    MOVL    28(DI),  AX
    MOVL    AX,    ((132+7)*4)(SP)  // h = H7

    WMSGFill(0);WMSGFill(1);WMSGFill(2);WMSGFill(3);WMSGFill(4);WMSGFill(5); WMSGFill(6);  //W0-W6
    WMSGFill(7);WMSGFill(8);WMSGFill(9);WMSGFill(10);WMSGFill(11);WMSGFill(12)  //W7-W12
    WMSGFill(13);WMSGFill(14);WMSGFill(15) //W13-W15
    WMSGHandle(16);WMSGHandle(17);WMSGHandle(18);WMSGHandle(19);WMSGHandle(20)
    WMSGHandle(21);WMSGHandle(22);WMSGHandle(23);WMSGHandle(24);WMSGHandle(25);
    WMSGHandle(26);WMSGHandle(27);WMSGHandle(28);WMSGHandle(29);WMSGHandle(30);
    WMSGHandle(31);WMSGHandle(32);WMSGHandle(33);WMSGHandle(34);WMSGHandle(35);
    WMSGHandle(36);WMSGHandle(37);WMSGHandle(38);WMSGHandle(39);WMSGHandle(40);
    WMSGHandle(41);WMSGHandle(42);WMSGHandle(43);WMSGHandle(44);WMSGHandle(45);
    WMSGHandle(46);WMSGHandle(47);WMSGHandle(48);WMSGHandle(49);WMSGHandle(50);
    WMSGHandle(51);WMSGHandle(52);WMSGHandle(53);WMSGHandle(54);WMSGHandle(55);
    WMSGHandle(56);WMSGHandle(57);WMSGHandle(58);WMSGHandle(59);WMSGHandle(60);
    WMSGHandle(61);WMSGHandle(62);WMSGHandle(63);WMSGHandle(64);WMSGHandle(65);
    WMSGHandle(66);WMSGHandle(67);WMSGHandle2(0);WMSGHandle2(1);WMSGHandle2(2);
    WMSGHandle2(3);WMSGHandle2(4);WMSGHandle2(5);WMSGHandle2(6);WMSGHandle2(7);
    WMSGHandle2(8);WMSGHandle2(9);WMSGHandle2(10);WMSGHandle2(11);WMSGHandle2(12);
    WMSGHandle2(13);WMSGHandle2(14);WMSGHandle2(15);WMSGHandle2(16);WMSGHandle2(17);
    WMSGHandle2(18);WMSGHandle2(19);WMSGHandle2(20);WMSGHandle2(21);WMSGHandle2(22);
    WMSGHandle2(23);WMSGHandle2(24);WMSGHandle2(25);WMSGHandle2(26);WMSGHandle2(27);
    WMSGHandle2(28);WMSGHandle2(29);WMSGHandle2(30);WMSGHandle2(31);WMSGHandle2(32);
    WMSGHandle2(33);WMSGHandle2(34);WMSGHandle2(35);WMSGHandle2(36);WMSGHandle2(37);
    WMSGHandle2(38);WMSGHandle2(39);WMSGHandle2(40);WMSGHandle2(41);WMSGHandle2(42);
    WMSGHandle2(43);WMSGHandle2(44);WMSGHandle2(45);WMSGHandle2(46);WMSGHandle2(47);
    WMSGHandle2(48);WMSGHandle2(49);WMSGHandle2(50);WMSGHandle2(51);WMSGHandle2(52);
    WMSGHandle2(53);WMSGHandle2(54);WMSGHandle2(55);WMSGHandle2(56);WMSGHandle2(57);
    WMSGHandle2(58);WMSGHandle2(59);WMSGHandle2(60);WMSGHandle2(61);WMSGHandle2(62);WMSGHandle2(63);
    SM3ROUND0(0);SM3ROUND0(1);SM3ROUND0(2);SM3ROUND0(3);SM3ROUND0(4);SM3ROUND0(5)
    SM3ROUND0(6);SM3ROUND0(7);SM3ROUND0(8);SM3ROUND0(9);SM3ROUND0(10);SM3ROUND0(11)
    SM3ROUND0(12);SM3ROUND0(13);SM3ROUND0(14);SM3ROUND0(15)
    SM3ROUND1(16);SM3ROUND1(17);SM3ROUND1(18);SM3ROUND1(19);SM3ROUND1(20);SM3ROUND1(21)
    SM3ROUND1(22);SM3ROUND1(23);SM3ROUND1(24);SM3ROUND1(25);SM3ROUND1(26);SM3ROUND1(27)
    SM3ROUND1(28);SM3ROUND1(29);SM3ROUND1(30);SM3ROUND1(31);SM3ROUND1(32);SM3ROUND1(33)
    SM3ROUND1(34);SM3ROUND1(35);SM3ROUND1(36);SM3ROUND1(37);SM3ROUND1(38);SM3ROUND1(39)
    SM3ROUND1(40);SM3ROUND1(41);SM3ROUND1(42);SM3ROUND1(43);SM3ROUND1(44);SM3ROUND1(45)
    SM3ROUND1(46);SM3ROUND1(47);SM3ROUND1(48);SM3ROUND1(49);SM3ROUND1(50);SM3ROUND1(51)
    SM3ROUND1(52);SM3ROUND1(53);SM3ROUND1(54);SM3ROUND1(55);SM3ROUND1(56);SM3ROUND1(57)
    SM3ROUND1(58);SM3ROUND1(59);SM3ROUND1(60);SM3ROUND1(61);SM3ROUND1(62);SM3ROUND1(63)
    MOVL    dig+0(FP),   BX
    LEAL    528(SP),    DI
    MOVL    (0*4)(DI),  AX
    XORL    AX,     (0*4)(BX)
    MOVL    (1*4)(DI),  AX
    XORL    AX,     (1*4)(BX)
    MOVL    (2*4)(DI),  AX
    XORL    AX,     (2*4)(BX)
    MOVL    (3*4)(DI),  AX
    XORL    AX,     (3*4)(BX)
    MOVL    (4*4)(DI),  AX
    XORL    AX,     (4*4)(BX)
    MOVL    (5*4)(DI),  AX
    XORL    AX,     (5*4)(BX)
    MOVL    (6*4)(DI),  AX
    XORL    AX,     (6*4)(BX)
    MOVL    (7*4)(DI),  AX
    XORL    AX,     (7*4)(BX)

    ADDL	$64, SI
	CMPL	SI, 560(SP)
	JB	loop

end:
    RET

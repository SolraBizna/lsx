-- lazy check for commonly-installed versions of Lua that are not compatible
if _VERSION == "Lua 5.0" or _VERSION == "Lua 5.1" then
   io.stderr:write("gen_twofish_tables requires Lua 5.2 or later.\n")
   os.exit(1)
end

print[[
/*
   Tables like these originally showed up in GPG's Twofish implementation. That
 implementation is in the public domain. I probably wouldn't have thought to
 make many of these optimizations myself, especially given my poor
 understanding of the mathematics involved. Helpfully, the original code
 included many comments detailing the origin and purpose of each table. These
 comments allowed me to produce code to generate the tables, and lead me to
 a greater understanding of the implementation than I could have gotten simply
 from blindly copying said tables (and large chunks of the associated code).
   These helpful comments are reproduced exactly in this file. I did not write
 or modify any of the comments. Some of them reference symbols, constructs,
 and implementation decisions that are in the GPG implementation but not this
 one. Caveat reader.
   I also owe a lot to the help of Nikoli Dryden, whose mathematical and
 cryptological background is far stronger than mine.
                                               -SB
*/
]]

local function printf(format,...) return io.write(format:format(...)) end

-- slow_shift_mul is based on code from Nikoli Dryden, used with permission.
-- Thanks, Nik! His comments follow:
-- Do multiplication in GF(2^8) slowly by shifting.
-- Based upon code from "The Laws of Cryptography" by Neal R. Wagner.
-- See: http://www.cs.utsa.edu/~wagner/laws/FFM.html
local function slow_shift_mul(a, b, polynomial)
   local r,t= 0,0
   while a ~= 0 do
      if bit32.btest(a, 1) then r = bit32.bxor(r, b) end
      t = bit32.band(b, 128)
      b = bit32.band(bit32.lshift(b,1), 255)
      if t ~= 0 then b = bit32.bxor(b, polynomial) end
      a = bit32.rshift(a, 1)
   end
   return r
end
local MDS_POLYNOMIAL = 105
local function mds_poly_mul(a,b) return slow_shift_mul(a,b,MDS_POLYNOMIAL) end
local RS_POLYNOMIAL = 77
local function rs_poly_mul(a,b) return slow_shift_mul(a,b,RS_POLYNOMIAL) end

-- "rotate right one bit" table for 4 bits
local ror1 = {}
for n=0,15 do
   ror1[n] = bit32.bor(bit32.rshift(n,1),bit32.band(bit32.lshift(n,3),15))
end
-- make one of q0/q1 from the provided tables
local function make_q(t0, t1, t2, t3)
   local ret = {}
   for x=0,255 do
      local a0, b0 = bit32.rshift(x,4), bit32.band(x,15)
      local a1 = bit32.bxor(a0, b0)
      local b1 = bit32.bxor(a0, ror1[b0], bit32.band(a0*8,15))
      local a2, b2 = t0[a1], t1[b1]
      local a3 = bit32.bxor(a2, b2)
      local b3 = bit32.bxor(a2, ror1[b2], bit32.band(a2*8,15))
      local a4, b4 = t2[a3], t3[b3]
      ret[x] = 16 * b4 + a4
   end
   return ret
end

print[[
/* These two tables are the q0 and q1 permutations, exactly as described in
 * the Twofish paper. */
]]

local q0 = make_q(
   {[0]=0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4},
   {[0]=0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD},
   {[0]=0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1},
   {[0]=0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA}
)
local q1 = make_q(
   {[0]=0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5},
   {[0]=0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8},
   {[0]=0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF},
   {[0]=0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA}
)

print("static const uint8_t q0[256] = {")
for n=0,255 do
   if n % 8 == 0 then io.write("  ") end
   printf("0x%02X, ", q0[n]);
   if n % 8 == 7 then io.write("\n") end
end
print("};")

print("static const uint8_t q1[256] = {")
for n=0,255 do
   if n % 8 == 0 then io.write("  ") end
   printf("0x%02X, ", q1[n]);
   if n % 8 == 7 then io.write("\n") end
end
print("};\n")

print[[
/* These MDS tables are actually tables of MDS composed with q0 and q1,
 * because it is only ever used that way and we can save some time by
 * precomputing.  Of course the main saving comes from precomputing the
 * GF(2^8) multiplication involved in the MDS matrix multiply; by looking
 * things up in these tables we reduce the matrix multiply to four lookups
 * and three XORs.  Semi-formally, the definition of these tables is:
 * mds[0][i] = MDS (q1[i] 0 0 0)^T  mds[1][i] = MDS (0 q0[i] 0 0)^T
 * mds[2][i] = MDS (0 0 q1[i] 0)^T  mds[3][i] = MDS (0 0 0 q0[i])^T
 * where ^T means "transpose", the matrix multiply is performed in GF(2^8)
 * represented as GF(2)[x]/v(x) where v(x)=x^8+x^6+x^5+x^3+1 as described
 * by Schneier et al, and I'm casually glossing over the byte/word
 * conversion issues. */
]]

local MDS = {
   {0x01, 0xEF, 0x5B, 0x5B},
   {0x5B, 0xEF, 0xEF, 0x01},
   {0xEF, 0x5B, 0x01, 0xEF},
   {0xEF, 0x01, 0xEF, 0x5B},
}

local mdsq = {{},{},{},{}}
for n=0,255 do
   local q0_n,q1_n = q0[n],q1[n]
   mdsq[1][n] = bit32.bor(mds_poly_mul(q1_n, MDS[1][1]),
                          bit32.lshift(mds_poly_mul(q1_n, MDS[2][1]),8),
                          bit32.lshift(mds_poly_mul(q1_n, MDS[3][1]),16),
                          bit32.lshift(mds_poly_mul(q1_n, MDS[4][1]),24))
   mdsq[2][n] = bit32.bor(mds_poly_mul(q0_n, MDS[1][2]),
                          bit32.lshift(mds_poly_mul(q0_n, MDS[2][2]),8),
                          bit32.lshift(mds_poly_mul(q0_n, MDS[3][2]),16),
                          bit32.lshift(mds_poly_mul(q0_n, MDS[4][2]),24))
   mdsq[3][n] = bit32.bor(mds_poly_mul(q1_n, MDS[1][3]),
                          bit32.lshift(mds_poly_mul(q1_n, MDS[2][3]),8),
                          bit32.lshift(mds_poly_mul(q1_n, MDS[3][3]),16),
                          bit32.lshift(mds_poly_mul(q1_n, MDS[4][3]),24))
   mdsq[4][n] = bit32.bor(mds_poly_mul(q0_n, MDS[1][4]),
                          bit32.lshift(mds_poly_mul(q0_n, MDS[2][4]),8),
                          bit32.lshift(mds_poly_mul(q0_n, MDS[3][4]),16),
                          bit32.lshift(mds_poly_mul(q0_n, MDS[4][4]),24))
end

print("static const uint32_t mdsq[4][256] = {")
for n=1,4 do
   print("  {")
   for m=0,255 do
      if m % 4 == 0 then io.write("    ") end
      printf("0x%08X, ", mdsq[n][m]);
      if m % 4 == 3 then io.write("\n") end
   end
   print("  },")
end
print("};\n")

print[[
/* The exp_to_poly and poly_to_exp tables are used to perform efficient
 * operations in GF(2^8) represented as GF(2)[x]/w(x) where
 * w(x)=x^8+x^6+x^3+x^2+1.  We care about doing that because it's part of the
 * definition of the RS matrix in the key schedule.  Elements of that field
 * are polynomials of degree not greater than 7 and all coefficients 0 or 1,
 * which can be represented naturally by bytes (just substitute x=2).  In that
 * form, GF(2^8) addition is the same as bitwise XOR, but GF(2^8)
 * multiplication is inefficient without hardware support.  To multiply
 * faster, I make use of the fact x is a generator for the nonzero elements,
 * so that every element p of GF(2)[x]/w(x) is either 0 or equal to (x)^n for
 * some n in 0..254.  Note that that caret is exponentiation in GF(2^8),
 * *not* polynomial notation.  So if I want to compute pq where p and q are
 * in GF(2^8), I can just say:
 *    1. if p=0 or q=0 then pq=0
 *    2. otherwise, find m and n such that p=x^m and q=x^n
 *    3. pq=(x^m)(x^n)=x^(m+n), so add m and n and find pq
 * The translations in steps 2 and 3 are looked up in the tables
 * poly_to_exp (for step 2) and exp_to_poly (for step 3).  To see this
 * in action, look at the CALC_S macro.  As additional wrinkles, note that
 * one of my operands is always a constant, so the poly_to_exp lookup on it
 * is done in advance; I included the original values in the comments so
 * readers can have some chance of recognizing that this *is* the RS matrix
 * from the Twofish paper.  I've only included the table entries I actually
 * need; I never do a lookup on a variable input of zero and the biggest
 * exponents I'll ever see are 254 (variable) and 237 (constant), so they'll
 * never sum to more than 491.	I'm repeating part of the exp_to_poly table
 * so that I don't have to do mod-255 reduction in the exponent arithmetic.
 * Since I know my constant operands are never zero, I only have to worry
 * about zero values in the variable operand, and I do it with a simple
 * conditional branch.	I know conditionals are expensive, but I couldn't
 * see a non-horrible way of avoiding them, and I did manage to group the
 * statements so that each if covers four group multiplications. */
]]

local rs_poly_to_exp = {}
local rs_poly_from_exp = {[0]=1}
local value = 1
repeat
   value = rs_poly_mul(value, 2)
   rs_poly_from_exp[#rs_poly_from_exp+1] = value
until value == 1
for n=0,#rs_poly_from_exp do
   rs_poly_to_exp[rs_poly_from_exp[n]-1] = n
end

assert(#rs_poly_to_exp == 254)

print("static const uint8_t rs_poly_to_exp[255] = {")
for n=0,254 do
   if n % 12 == 0 then io.write("  ") end
   printf("0x%02X, ", rs_poly_to_exp[n]%255);
   if n % 12 == 11 then io.write("\n") end
end
print("\n};")

print("static const uint8_t rs_poly_from_exp[492] = {")
for n=0,491 do
   if n % 12 == 0 then io.write("  ") end
   printf("0x%02X, ", rs_poly_from_exp[n%255]);
   if n % 12 == 11 then io.write("\n") end
end
print("\n};\n")

local RS = {
   {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
   {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
   {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
   {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03},
}

print[[
/* The RS matrix values, de-mystified, processed through rs_poly_to_exp. -SB */
]]

for row=1,4 do
   for column=1,8 do
      printf("#define RS_%i_%i 0x%02X\n", row, column, rs_poly_to_exp[RS[row][column]-1] % 255)
   end
end

print()

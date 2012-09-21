#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#define RSA_NUM_BITS 32
#define E_NUM_BITS 17
#define DEBUG 1

int applyExtendedEuclid(mpz_t e, mpz_t phi, mpz_t d)
{
	
	mpz_t x, y, z, a, b, c, lcm, div, temp, mul, tx, ty, tz;
	
	if(mpz_even_p(e))	
		return 0;
	
	mpz_init(x);
	mpz_init(y);
	mpz_init(z);
	
	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
		
	mpz_init(tx);
	mpz_init(ty);
	mpz_init(tz);
	
	mpz_init(div);
	mpz_init(temp);
	
	mpz_init_set_si(a, 1);
	mpz_init_set_si(b, 0);
	mpz_init_set(c, phi);
	mpz_init_set_si(x, 0);
	mpz_init_set_si(y, 1);
	mpz_init_set(z, e);

	do
	{
		mpz_init_set(tx, x);
		mpz_init_set(ty, y);
		mpz_init_set(tz, z);
		#if DEBUG
			printf("\n\n");
			mpz_out_str(NULL, 10, a);
			printf("\n");
			mpz_out_str(NULL, 10, b);
			printf("\n");
			mpz_out_str(NULL, 10, c);
			printf("\n\n");
			mpz_out_str(NULL, 10, x);
			printf("\n");	
			mpz_out_str(NULL, 10, y);
			printf("\n");
			mpz_out_str(NULL, 10, z);
			printf("\n\n");
		#endif
		mpz_tdiv_qr(div, z, c, z);
		mpz_mul(mul, x, div);
		mpz_sub(x, a, mul);
		mpz_mul(mul, y, div);
		mpz_sub(y, b, mul);
		mpz_init_set(a, tx);
		mpz_init_set(b, ty);
		mpz_init_set(c, tz);
	}while(mpz_cmp_si(z, 0L)!=0);	
	
	//LCM not 1
	if(mpz_cmp_si(tz, 1L)!=0)
	{
		return 0;
	}
	else
	{
		mpz_init_set(d, tx);
		return 1;
	}
}

int main()
{
	/*TODO: How will the numbers chosen be of "similar bit length" ?
	 */
		mpz_t p, q, n, phi, decp, decq, e, d;
		gmp_randstate_t randomState;
		int isPrimeP = 0, isPrimeQ = 0;
		
		//initialising random values
		mpz_init(p);
		mpz_init(q);
		mpz_init(n);
		mpz_init(decp);
		mpz_init(decq);
		mpz_init(phi);
		mpz_init(e);
		mpz_init(d);
		mpz_init_set_si(e, 65537L);
		//seeding random value
		gmp_randinit_default(randomState);
		gmp_randseed_ui(randomState, time(0));

		//generatnig primes
		do
		{
			mpz_urandomb(p, randomState ,RSA_NUM_BITS);
			isPrimeP = mpz_probab_prime_p(p, 10);
		}
		while(!isPrimeP);
		
		do
		{
			mpz_urandomb(q, randomState ,RSA_NUM_BITS);
			isPrimeQ = mpz_probab_prime_p(q, 10);
		}
		while(!isPrimeQ);
		
		//p*q
		mpz_mul(n , p , q);
		
		#if DEBUG
			mpz_out_str(NULL, 10, p);
			printf("\n");
			mpz_out_str(NULL, 10, q);
			printf("\n");
			mpz_out_str(NULL, 10, n);
			printf("\n");
			mpz_out_str(NULL, 10, decp);
			printf("\n");
			mpz_out_str(NULL, 10, decq);
			printf("\n");
		#endif
		
		//p - 1
		mpz_sub_ui(decp, p, 1);
		
		// q - 1 
		mpz_sub_ui(decq, q, 1);
		
		//Euler's totient function
		mpz_mul(phi, decp, decq);
		
		int foundE = 0;
		foundE = applyExtendedEuclid(e, phi, d);

		while(!foundE)
		{
			mpz_urandomb(e, randomState ,E_NUM_BITS);
			foundE = applyExtendedEuclid(e, phi, d);
		}

		#if DEBUG
			mpz_out_str(NULL, 10, e);
			printf("\n");
			mpz_out_str(NULL, 10, d);
			printf("\n");
		#endif
		
		if(mpz_cmp_si(d, 0L) < 0)
		{
			mpz_add(d, phi, d);
		}
		
		#if DEBUG
			printf("Positive D\n");
			mpz_out_str(NULL, 10, d);
			printf("\n");
		#endif
		return 0;
}


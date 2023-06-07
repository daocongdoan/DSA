using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

class DSASignatureExample
{
    static void Main()
    {
        

        BigInteger p = 107;
        BigInteger q = 53;
        

        BigInteger h = CalculateH(q, p);
        BigInteger g = FindG(h, p, q);

        BigInteger x = GeneratePrivateKey(q);
        BigInteger y = CalculatePublicKey(g, p, q, x);
        // Console.WriteLine("Input");
        // Console.WriteLine("p :" + p);
        // Console.WriteLine("q :" + q);
        // Console.WriteLine("g :" + g);
        // Console.WriteLine("x :" + x);
        // Console.WriteLine("y :" + y);
        //Console.WriteLine("Private Key: " + x.ToString());
        Console.WriteLine("Public Key (Khoa cong khai): " + y.ToString());

        Console.Write("Nhap du lieu can ky (vidu Hello world) : ");
        string message = Console.ReadLine();
        
        //byte[] data = Encoding.UTF8.GetBytes(message);

        BigInteger r, s;
        SignDSA(message, q, x, g, p, out r, out s);

        Console.Write("Nhap khoa cong khai (public key) : ");
        BigInteger publicKey = BigInteger.Parse(Console.ReadLine());
        Console.WriteLine("Signature (r): " + r.ToString());
        Console.WriteLine("Signature (s): " + s.ToString());

        bool isValid = VerifyDSA(message, q, publicKey, g, p, r, s);

        if (isValid)
        {
            Console.WriteLine("Signature is valid..");
        }
        else
        {
            Console.WriteLine("Signature is not valid!.");
        }
    }
    
    static BigInteger CalculateH(BigInteger q, BigInteger p)
    {
        BigInteger exponent = (p - 1) / q;
        BigInteger h = BigInteger.ModPow(2, exponent, p);
        return h;
    }

    static BigInteger FindG(BigInteger h, BigInteger p, BigInteger q)
    {
        for (BigInteger g = 2; g < p; g++)
        {
            //Console.WriteLine("Running: "+g);
            if (BigInteger.ModPow(g, q, p) == 1 && BigInteger.ModPow(g, (p - 1) / q, p) == h)
            {
                return g;
            }
        }

        throw new Exception("Cannot find g");
    }
    
    static BigInteger GeneratePrivateKey(BigInteger q)
    {
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            byte[] buffer = new byte[q.ToByteArray().Length];
            rng.GetBytes(buffer);

            BigInteger privateKey = new BigInteger(buffer);
            if (privateKey.Sign < 0)
            {
                privateKey = -privateKey;
            }

            privateKey = privateKey % (q - 1) + 1;

            return privateKey;
        }
    }

    static BigInteger CalculatePublicKey(BigInteger g, BigInteger p, BigInteger q, BigInteger x)
    {
        BigInteger publicKey = BigInteger.ModPow(g, x, p);
        return publicKey;
    }
    static BigInteger GenerateRandomBigInteger(Random random, BigInteger minValue, BigInteger maxValue)
    {
        BigInteger range = maxValue - minValue;
        byte[] bytes = new byte[range.ToByteArray().Length];
        random.NextBytes(bytes);
        BigInteger randomBigInt = new BigInteger(bytes);
        
        if (randomBigInt < 0)
        {
            randomBigInt = BigInteger.Negate(randomBigInt);
        }
        
        randomBigInt %= range;
        randomBigInt += minValue;

        return randomBigInt;
    }

    static void SignDSA(string message, BigInteger q, BigInteger x, BigInteger g, BigInteger p, out BigInteger r, out BigInteger s)
    {
        r = BigInteger.Zero;
        s = BigInteger.Zero;

        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            // do
            // {
                Console.WriteLine("Run");
                byte[] kBytes = new byte[q.ToByteArray().Length];
                rng.GetBytes(kBytes);
                Random random = new Random();
                BigInteger k = GenerateRandomBigInteger(random, 1, q);
                Console.WriteLine("k1 :" + k);
                r = BigInteger.ModPow(g, k, p) % q;
                Console.WriteLine("r :" + r);
                // if (r.Sign == 0)
                // {
                //     continue;
                // }

                BigInteger kInverse = ModInverse(k, q);

                BigInteger hash = hashResult(message);

                Console.WriteLine("k-1 :" + kInverse);
                Console.WriteLine("hash :" + hash);
                s = (kInverse * (hash + x * r)) % q;
                Console.WriteLine("s :" + s);
                //s = (s + q) % q; // Make sure s is positive

                // if (s.Sign == 0)
                // {
                //     continue;
                // }
            // }
            // while (r.Sign == 0 || s.Sign == 0);
        }
    }

    static bool VerifyDSA(string message, BigInteger q, BigInteger y, BigInteger g, BigInteger p, BigInteger r, BigInteger s)
    {
        // Console.WriteLine("Verify");
        // Console.WriteLine("s :" + s);
        // Console.WriteLine("p :" + p);
        // Console.WriteLine("q :" + q);
        // Console.WriteLine("y :" + y);
        // Console.WriteLine("g :" + g);
        // Console.WriteLine("r :" + r);

        BigInteger w = ModInverse(s, q);
        BigInteger hash = hashResult(message);

        BigInteger u1 = (hash * w) % q;
        BigInteger u2 = (r * w) % q;
        // Console.WriteLine("w :" + w);
        // Console.WriteLine("hash :" + hash);
        // Console.WriteLine("u1 :" + u1);
        // Console.WriteLine("u2 :" + u2);
       // Console.WriteLine("g :" + g);

        //BigInteger v = (BigInteger.ModPow(g, u1, p) * BigInteger.ModPow(y, u2, p)) % q;
        BigInteger v = ((BigInteger.ModPow(g, u1, p) * BigInteger.ModPow(y, u2, p)) % p) % q;
        Console.WriteLine("v :" + v);
        return v.Equals(r);
    }

    static BigInteger ModInverse(BigInteger a, BigInteger n)
    {
        BigInteger m0 = n;
        BigInteger y = 0, x = 1;

        if (n == 1)
        {
            return 0;
        }

        while (a > 1)
        {
            BigInteger q = a / n;
            BigInteger t = n;

            n = a % n;
            a = t;
            t = y;

            y = x - q * y;
            x = t;
        }

        if (x < 0)
        {
            x += m0;
        }

        return x;
    }

    // static BigInteger HashToBigInteger(byte[] data)
    // {
    //     using (SHA256 sha256 = SHA256.Create())
    //     {
    //         byte[] hash = sha256.ComputeHash(data);
    //         BigInteger result = new BigInteger(hash);
    //         return result;
    //     }
    // }

    //Hàm băm
    public static BigInteger hashResult(string input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = sha256.ComputeHash(inputBytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2")); // Convert each byte to hexadecimal string
            }
            

            BigInteger result = BigInteger.Abs(BigInteger.Parse(sb.ToString(), System.Globalization.NumberStyles.HexNumber));
            return result;
        }
    }
}



//Code thừa
//main
// Độ dài bit của p và q
        // int pBitLength = 2048;
        // int qBitLength = 256;

        // Tìm bộ số p và q
        //DSAParameters parameters = GenerateDSAParameters(pBitLength, qBitLength);
        //Tìm bộ số p và q
        //DSAParameters parameters = GenerateDSAParameters(pBitLength, qBitLength);

        // BigInteger a = new BigInteger(parameters.P!); // Chuyển đổi p từ byte[] sang BigInteger
        // BigInteger b = new BigInteger(parameters.Q!); // Chuyển đổi q từ byte[] sang BigInteger
        // Console.WriteLine("Check");
        // Console.WriteLine("a :" + a);
        // Console.WriteLine("b :" + b);
//end main
// //Tìm p,q:
    // static BigInteger GeneratePrimeNumber(Random random, BigInteger minValue, BigInteger maxValue)
    // {
    //     BigInteger prime;
    //     bool isPrime;

    //     do
    //     {
    //         prime = GenerateRandomNumber(random, minValue, maxValue);
    //         isPrime = IsPrime(prime);
    //     }
    //     while (!isPrime);

    //     return prime;
    // }

    // static BigInteger GenerateRandomNumber(Random random, BigInteger minValue, BigInteger maxValue)
    // {
    //     byte[] bytes = maxValue.ToByteArray();
    //     random.NextBytes(bytes);
    //     BigInteger number = new BigInteger(bytes);
    //     number = BigInteger.Abs(number);

    //     if (number < minValue)
    //     {
    //         number += minValue;
    //     }

    //     if (number > maxValue)
    //     {
    //         number %= maxValue;
    //         number += minValue;
    //     }

    //     return number;
    // }

    // static bool IsPrime(BigInteger number)
    // {
    //     if (number < 2)
    //     {
    //         return false;
    //     }

    //     if (number == 2 || number == 3)
    //     {
    //         return true;
    //     }

    //     if (number % 2 == 0 || number % 3 == 0)
    //     {
    //         return false;
    //     }

    //     BigInteger divisor = 6;

    //     while (divisor * divisor - 2 * divisor + 1 <= number)
    //     {
    //         if (number % (divisor - 1) == 0)
    //         {
    //             return false;
    //         }
    //         if (number % (divisor + 1) == 0)
    //         {
    //             return false;
    //         }
    //         divisor += 6;
    //     }
    //     return true;
    // }

    // static BigInteger FindNextPrime(BigInteger number)
    // {
    //     while (!IsPrime(number))
    //     {
    //         number++;
    //     }

    //     return number;
    // }
    // static DSAParameters GenerateDSAParameters(int pBitLength, int qBitLength)
    // {
    //     DSAParameters parameters;

    //     using (var dsa = DSA.Create())
    //     {
    //         // Generate p and q
    //         dsa.KeySize = pBitLength;
    //         parameters = dsa.ExportParameters(true);

    //         // Check if q length is correct
    //         while (parameters.Q!.Length * 8 != qBitLength)
    //         {
    //             parameters = dsa.ExportParameters(true);
    //         }
    //     }

    //     return parameters;
    // }
    // static BigInteger FindnnG(BigInteger p, BigInteger q)
    // {
    //     BigInteger g = 2;

    //     while (BigInteger.ModPow(g, q, p) != 1)
    //     {
    //         g++;
    //     }

    //     return g;
    // }

    // static BigInteger ModPowH(BigInteger x, BigInteger y, BigInteger p)
    // {
    //     BigInteger res = 1;
    //     x = x % p;

    //     while (y > 0)
    //     {
    //         if (y % 2 == 1)
    //         {
    //             res = (res * x) % p;
    //         }

    //         y = y >> 1;
    //         x = (x * x) % p;
    //     }

    //     return res;
    // }

// static BigInteger FindGenerator(BigInteger p, BigInteger q)
    // {
    //     BigInteger h = 2;

    //     while (h < p - 1)
    //     {

    //         BigInteger g = BigInteger.ModPow(h, (p - 1) / q, p);

    //         if (BigInteger.ModPow(g, q, p) == 1)
    //         {
    //             return g;
    //         }

    //         h++;
    //     }

    //     return BigInteger.Zero;
    // }


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSA
{
    public class LinearCongruentialGenerator
    {
        private long _backupSeed;
        private long _seed;
        private long _a;
        private long _c;
        private long _m;

        public LinearCongruentialGenerator(long a, long c, long m, long seed)
        {
            _a = a;
            _c = c;
            _m = m;
            _seed = seed;
            _backupSeed = seed;
        }
        public void Reset() => _seed = _backupSeed;
        public long Next()
        {
            _seed = (_a * _seed + _c) % _m;
            return _seed;
        }

        public long GetPeriod()
        {
            var initialSeed = _seed;
            var firstNumber = Next();
            var previousNumber = 0L;
            var currentNumber = firstNumber;
            var period = 1;

            HashSet<long> seenValues = new HashSet<long>();

            while (true)
            {
                previousNumber = currentNumber;
                currentNumber = Next();
                if (currentNumber == previousNumber || currentNumber == initialSeed || currentNumber == firstNumber)
                {
                    break;
                }
                period++;
            }

            return period;
        }
    }
}
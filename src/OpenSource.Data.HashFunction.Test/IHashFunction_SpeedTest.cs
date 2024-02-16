﻿using Moq;
using System;
using System.Collections.Generic;
using OpenSource.Data.HashFunction.Test._Mocks;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace OpenSource.Data.HashFunction.Test
{
    public abstract class IHashFunction_SpeedTest
    {
        protected abstract IReadOnlyDictionary<string, IHashFunction> TestHashFunctions { get; }

        private const int SINGLE_BLOCK_SIZE = 12000000; // 32 MB

        private const int MULTIPLE_ITEMS_SIZE = 0x80; // 128 B
        private const int MULTIPLE_ITEMS_COUNT = 0x10000; // 64 K


        // xUnit doesn't have a better way to do this
        private readonly bool _SkipAllTests = true;

        #region SingleBlock

        #region ComputeHash

        [Fact]
        public void IHashFunction_SpeedTest_SingleBlock_ComputeHash_ByteArray()
        {
            IHashFunction_SpeedTest_SingleBlock((sw, testHashFunction, testBytes) => {
                sw.Start();
                {
                    testHashFunction.ComputeHash(testBytes);
                }
                sw.Stop();

                return true;
            });

        }

        #endregion

        private void IHashFunction_SpeedTest_SingleBlock(Func<Stopwatch, IHashFunction, byte[], bool> computeHash)
        {
            if (_SkipAllTests)
            {
                Console.Write("Skipped, unset _SkipAllTests in IHashFunction_SpeedTest.cs");
                return;
            }


            var testBytes = new byte[SINGLE_BLOCK_SIZE];

            (new Random())
                .NextBytes(testBytes);


            var sw = new Stopwatch();

            foreach (var testHashFunction in TestHashFunctions.OrderBy(kv => kv.Key))
            {
                // Test if computeHash results in a valid test and initialize any lazy settings
                if (!computeHash(sw, testHashFunction.Value, testBytes))
                    continue;

                sw.Reset();


                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
#if !NETCOREAPP1_1_OR_GREATER
                Thread.CurrentThread.Priority = ThreadPriority.AboveNormal;
#endif

                // Real test
                var computeCount = 0;
                while (sw.Elapsed < new TimeSpan(0, 0, 0, 1, 0) || computeCount < 3)
                {
                    computeHash(sw, testHashFunction.Value, testBytes);
                    ++computeCount;
                }


                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.Normal;
#if !NETCOREAPP1_1_OR_GREATER
                Thread.CurrentThread.Priority = ThreadPriority.Normal;
#endif


                var totalBytesComputedAgainst = ((long) testBytes.Length) * computeCount;

                Console.WriteLine("{0, -40} {1:F2} MB/s ({2} B in {3:F3} ms)",
                    testHashFunction.Key + ":",
                    totalBytesComputedAgainst / 1048576.0d / sw.Elapsed.TotalSeconds,
                    totalBytesComputedAgainst,
                    sw.ElapsedMilliseconds);

                sw.Reset();
            }
        }

#endregion

#region MultipleItems

#region ComputeHash

        [Fact]
        public void IHashFunction_SpeedTest_MultipleItems_ComputeHash_ByteArray()
        {
            IHashFunction_SpeedTest_MultipleItems((sw, testHashFunction, count, testBytes) =>
            {
                sw.Start();

                for (int x = 0; x < count; ++x)
                    testHashFunction.ComputeHash(testBytes);

                sw.Stop();

                return true;
            });

        }

#endregion

        protected void IHashFunction_SpeedTest_MultipleItems(Func<Stopwatch, IHashFunction, int, byte[], bool> computeHash)
        {
            if (_SkipAllTests)
            {
                Console.Write("Skipped, unset _SkipAllTests in IHashFunction_SpeedTest.cs");
                return;
            }

            var testBytes = new byte[MULTIPLE_ITEMS_SIZE];

            (new Random())
                .NextBytes(testBytes);



            var sw = new Stopwatch();

            foreach (var testHashFunction in TestHashFunctions.OrderBy(kv => kv.Key))
            {
                // Test if computeHash results in a valid test and initialize any lazy settings
                if (!computeHash(sw, testHashFunction.Value, 1, testBytes))
                    continue;

                sw.Reset();


                // Real test
                computeHash(sw, testHashFunction.Value, MULTIPLE_ITEMS_COUNT, testBytes);

                Console.WriteLine("{0, -40} {1:F2} MB/s ({2} B in {3:F3} ms)",
                    testHashFunction.Key + ":",
                    (testBytes.Length * MULTIPLE_ITEMS_COUNT) / (1048510.0d) / ((double) sw.ElapsedTicks / TimeSpan.TicksPerSecond),
                    testBytes.Length * MULTIPLE_ITEMS_COUNT,
                    ((double)sw.ElapsedTicks / TimeSpan.TicksPerMillisecond));

                sw.Reset();
            }
        }

#endregion

    }

}

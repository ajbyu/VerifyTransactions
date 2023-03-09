using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using EllipticCurve;

namespace VerifyTransactions
{
    class Program
    {
        static void Main(string[] args)
        {

            // This task will require you to use ECC with the secp256k1 curve.
            // In a previous assignment you performed ECC with the secp256k1 curve using the Starkbank ecdsa-dotnet package.
            // It is recommended, but not required to use that again. This project has that package included.
            // Documentation/examples for that package can be found here: https://github.com/starkbank/ecdsa-dotnet

            // This is a String representation of a private EEC key in PEM format so you don't have to deal with files.
            // Leave Alone
            String privateKeyPEMImport = @"-----BEGIN EC PRIVATE KEY-----
            MHICAQEEIF0F4K5pYZ0SDv5XDfyIZmG5uK2d + IxT + P4oavXshX0VoAcGBSuBBAAK
            oUIABM8tMj1 / vmFHmzHqkMdhJhUUktLvWJD8Odvj42r5 + yfeW0AB8gtuwDDvPSzf
            cv3YH6sT36jk7vO + bkW1 + gEENuM =
            -----END EC PRIVATE KEY---- - ";

            // This code gets the Private ECC key from the PEM Import and the corresponding Public ECC key.
            // It is provided to smooth your way to successfully completing this task.
            // Leave Alone
            PrivateKey privateKey1 = EllipticCurve.PrivateKey.fromPem(privateKeyPEMImport);
            PublicKey publicKey1 = privateKey1.publicKey();


            // This String array contains 28 messages. You will be evaluating them.
            // Leave Alone
            string[] messages =
            {
                "Aomer",
                "Aragorn",
                "Arwen Evenstar",
                "Bilbo Baggins",
                "Boromir",
                "Denethor",
                "Elrond", 
                "Eomer",
                "Eowyn",
                "Faramir",
                "Frodo Baggins",
                "Galadriel",
                "Gandalf the White",
                "Gimli",
                "Glorfindel",
                "Gollum",
                "Grima Wormtongue",
                "Legolas",
                "Meriadoc Brandybuck",
                "Peregrin Took",
                "Samwise Gamgee",
                "Saruman the White",
                "Sauron",
                "Shadowfax",
                "Shelob",
                "Theoden",
                "Tom Bombadil",
                "Treebeard"
            };


            // This String array contains 28 ECC signatures for you to verify with their corresponding message.
            // The first signature in the array corresponds to the first message in the message array
            // The last signature in the array corresponds to the last message in the message array
            // The signatures have been converted to Base64 format so they can be treated as strings
            // In your code, you will need to use the Signature.fromBase64() method to convert from Strings to Signature objects
            // Leave Alone
            string[] signatures =
            {
                "MEYCIQD6hyT9+RsXGc+6lUeMIlr8eZiBV7PevCnXWs1zRr7sYwIhAN4Gov+vZLvYinCWS8VwYw5xhe16vgcmq5+tWbBP6a1j",
                "MEUCIQCfM6ZWDEHqDjUdza0LsmnuzGMiU7GvzzkUvteqr0XqagIgGPoBq6sfKNnyzYRjv77k2bHxwe1KlQdVsUqSOXEi4O0=",
                "MEYCIQDKyJP8HOG6vajSxTzc9Pgr09zlP13oCkO/Trxe2r+knwIhAP81NsJwfQui96+sl40858wIxzMUCv2SqMiP2fNzw7gq",
                "MEUCIEA31Ph9P/IsLh1XZ0eyw1hDrctM2EZVB/YZN/35VRlBAiEA75qHz7UNvE6YRQjrGCfet4fWgpGjY1IgLwcEqg4XJgw=",
                "MEUCIFmYx6s3HDlN3fzxJbfkqanRuYKWTXQbGjdEzdlZCzLRAiEAzkQ5KQrk/Wn6nhLMbQ/99TmwgtrTv6OFtKA9jpQL3YQ=",
                "MEUCIQDL85EexddL1T1TNRWpQQWMl3SNY1a04ALivzAmk550XQIgcKBlWmo/ENKru4elNHm1nO2mNBgnW6tSGtgvdpA3J7I=",
                "MEUCIHjxI+QDi9wt9uBllhzuT0gHyPBv6efhUeqzrZUFnV8kAiEAgtzQCyLH7ZZZMOuCbMAkkiJF8ccUOpAetD9Nk64tDy0=",
                "MEQCIECrrao6GaZlk9GEj2cDACqBM1wpabQwrdaNPr+VT9NqAiBRtzMe3FYKDO5S+QfFzn6zJY031y6mfw55kaagDbqfCg==",
                "MEUCIQDetGow+tPPI21ZvADprnSjTuvmwyd+RWr3WAOGCfEpkAIgOjrUz6cRNSei2lzNe6itURewXWs6tt+FB9g+K9H7Wes=",
                "MEQCIBEj6yM4zLHdc1MQ5gVhMBjPnUpNeMYhuaQBdxvPffsaAiA1SHlYsa8o245g2Gh2sVBhSLi/b4NbqCmIFR2BPbkEWg==",
                "MEQCIAFBPEtk+RaOvmO2OKkqIM7/UvxTEJZqSsTnJRZCwvY7AiAd7DFaevr+vzHMZmRhsks5RGznebOp7hw8beCRshcBuQ==",
                "MEUCIBWIowzsnQpwwyqTv/wUwFFKmy6uNJUlmwTMcc/paZPiAiEAtmtgjs0SrwYJioJjlu/gt1mpa5PGN5g9uGb3Blx6z5k=",
                "MEUCIBpKbAOAyLk6PgL4RXo4vmQOhKsnFReZfa37xLifjROGAiEA3pfBBEkIS5QJUSpkFOTwnwL3r/yftFbvthLv0EHM9Zk=",
                "MEUCID96KJnnXa821CdsZNNsKfdhnXpWu/kIbs89381uLxvIAiEAu+xiXht444pT3d5Oy5umOMSLwELtugNBZg980IWD350=",
                "MEUCIG1ycKk6AxdhGIzoUE6xLnNKC14zK4IwimYLpG9YLYJqAiEA31mKAPl0OUo97AcZDwPyL1b5xKCP6jKTPnFyfUXuj3s=",
                "MEYCIQCA3Ja6KbyMzAmHLuAC/Id1ZxqYIU6uIGDyqkj5hEgC+wIhAN4iwBN1rHUHNSds4SM/VG0IzrONpxqPQaHO130hmwH3",
                "MEUCIEYqQ3mSxFfLcRPYn+Vq7R+fReB8G70HBvH4GoSyAgsEAiEA9UYgHCC+ID5sVxpP/69C5i/scckOgF6mcuSrIHf9eoA=",
                "MEYCIQDaM24U+o5OUuostCunGLqGJUfsfV4j5g44mmeZuvt0cQIhAIXfaUMcLkDc99jdpfxr1wMecTQPNOO8MB+BGfJAatov",
                "MEQCICQO8XKWLTL2/e3ARIXRZfRky8Kaj9ssNXsjNqkincIlAiBWBzEA9oyPUC4nc572c0PAnLKmzsi9SdGs+6GhTwXqxg==",
                "MEUCIQDlEHRIYfprvU6Kblp7U14G1AL8sptrJ5M4d0AMMGHKtwIgKsWM29E6iMvPoS9oGcD3i7Ru8N/mrVKPHPk/ZbZx0Bs=",
                "MEUCIQCDuEzj+Cbjt0AkKIkVUzFlzQOhdH0JpJu3wy6awSpiUgIgYQ6Y77WXo1fqSEpkXFxD5TW+ikewAvpXKdzfR04oHZg=",
                "MEUCIQDyo8fJiB10Bc0rdG6OXXHBv+VajOylcI3WkDDr8yFbdgIgV0ykKf4kOIeRf6ubC+hrMPhl56vRMZDV/1ZSpRUxJa4=",
                "MEQCIBzN3ZQ0L/EEa5wQLeDtu1v1GGEbVSd6KGoW9zq0wyezAiA/XhDCEnReS+s4net1eOTm+hPruZv00qnfejCzNXAgKQ==",
                "MEUCIQCx6ksg9D9SZcop5DE0h51Jm7JgDjecGqSTf6pcptMZ1QIgBVkRs7MBdYvcXfGIM29jDQ20TPb4x8cZfrShdHwjmFU=",
                "MEYCIQCSIYOoenTWhvrN+5x8sjKNQRXvuFlWB2n1TYfN/YIFKAIhAJRq9IobrU0Nlt4QTZzMQn6Dj4knhHMPQKhNUOFpE85H",
                "MEUCIQC2c/bY2ZbS/iof+axdXUAEkBBr6wtbnzU1jEsFgEqIXAIgb7o0EKqOcZVK0wJCZEfdwxTYmJghWn5N3Wv2VVK+Ouc=",
                "MEUCIDH87F1p9cmcrzRPVsGbGLq6W19qpqcOyA57F+s1QdwqAiEA6x41qpDgbjCmGC+R/UU5iElhUvDxv1UWJUe/8kQ338g=",
                "MEQCIGqepS6wSNyKopCdQ1pdvq0Olfs1/xFaWeSWC7878ib3AiBpKKzmiPqdZKuv8U9gKoM4TPZLG6Uv//a8dprCe3g4xg=="
            };

            // Your task is to determine how many message signatures are valid.
            // You might also choose to find which signatures are invalid (if any).
            // You will need to use the Ecdsa.verify() method that was used in the Blockchain lab. It takes three arguments.
            // The messages are strings and do not need to be converted
            // The signatures are encoded as Base64 strings and need to be converted to Signature objects using the Signature.fromBase64() method
            // The valid signatures were all signed with the same private key (provided above) and can be verified with the corresponding public key (provided above).
            // You can solve this however you like, but a for loop is a good place to start

            int numMessages = messages.Length;

            List<string> validMessages = new List<string>();

            List<string> invalidMessages = new List<string>();

            //Check signature validities
            for (int i = 0; i < numMessages; i++)
            {
                if (Ecdsa.verify(messages[i], Signature.fromBase64(signatures[i]), publicKey1))
                {
                    validMessages.Add(messages[i]);
                }
                else
                {
                    invalidMessages.Add(messages[i]);
                }
            }

            //Print results
            Console.WriteLine("SIGNATURE VALIDITY");
            Console.WriteLine("--------------------------------------------------------");
            Console.WriteLine($"Number of valid signatures:   {validMessages.Count()}");
            Console.WriteLine($"Number of invalid signatures: {invalidMessages.Count()}");
            Console.WriteLine("--------------------------------------------------------");
            Console.WriteLine("Valid messages: \n");
            foreach (string sig in validMessages) { Console.WriteLine(sig); }
            Console.WriteLine("\n");
            Console.WriteLine("Invalid messages: \n");
            foreach (string sig in invalidMessages) { Console.WriteLine(sig); }

        }
    }
}

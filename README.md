# kaurna
Tool for securely storing secrets using AWS KMS.  Named after O. kaurna, the southern sand octopus, due to its skill at hiding from predators.

Random notes on my development style:

-I'll often have return statements even if letting the function run to the end would also work.  This is to make it clear where it exits; it doesn't serve a strict functional purpose.

-I'm a fan of writing python in fairly few lines at times.  It's a bad practice and one I'll clean up once the project is done, but I find it makes development easier when there's a lot of churn because it minimizes the chance of a change in one line affecting another.

Relies on boto >= 2.38 and pycrypto.  Unit tests rely on mock and nose.

The file example_policy.json contains a policy template that can be used to create an IAM policy for a kaurna user.  Replace <KAURNA_KEY_ARN> with the ARN of the kaurna key in your account and <AUTHORIZED ENTITY NAME> (yep, spaces are okay) with the name of the user.  If a user should have access to multiple entity's secrets, the second block (lines 20-34) can be repeated with different names within the same policy.

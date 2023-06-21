import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBasicBilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;

public class PointchevalSandersExampleCode {
    public static void doComputations() {
        // Choose number of messages r
        int r = 3;

        // BN pairing is type 3 and we specify a 100 bit security parameter
        BilinearGroup bilinearGroup = new BarretoNaehrigBasicBilinearGroup(100);

        // Let's collect the values for our pp
        Group groupG1 = bilinearGroup.getG1();
        Group groupG2 = bilinearGroup.getG2();
        Group groupGT = bilinearGroup.getGT();
        BilinearMap e = bilinearGroup.getBilinearMap();
        BigInteger p = groupG1.size();
        Zn zp = bilinearGroup.getZn();
        System.out.println("Generated bilinear group of order " + p);

        // Generate secret key
        Zn.ZnElement x = zp.getUniformlyRandomElement();
        RingElementVector y = zp.getUniformlyRandomElements(r); //computes a vector of r random numbers y_0, ..., y_(r-1)

        System.out.println("x = " + x);
        System.out.println("y = " + y);

        // Generate public key
        GroupElement tildeg = groupG2.getUniformlyRandomElement();
        GroupElement tildeX = tildeg.pow(x).precomputePow(); // this computes X = tildeg^x as above and runs precomputations to speed up later pow() calls on tildeX
        GroupElementVector tildeY = tildeg.pow(y).precomputePow(); // because y is a vector, this yields a vector of values tildeg.pow(y_0), tildeg.pow(y_1), ...
        System.out.println("tildeg = " + tildeg);
        System.out.println("tildeX = " + tildeX);
        System.out.println("tildeY = " + tildeY);

        // Preparing messages ("Hello PS sigs", 42, 0, 0, ...)
        RingElementVector m = new RingElementVector(
                bilinearGroup.getHashIntoZGroupExponent().hash("Hello PS sigs"),
                zp.valueOf(42)).pad(zp.getZeroElement(), r);

        // Computing signature
        GroupElement sigma1 = groupG1.getUniformlyRandomNonNeutral().computeSync(); // h
        GroupElement sigma2 = sigma1.pow(x.add(y.innerProduct(m))).computeSync(); // h^{x + sum(y_i*m_i)}
        // The compute() call is optional but will cause sigma1 and sigma2 to be computed concurrently in the background.
        System.out.println("sigma1 = " + sigma1);
        System.out.println("sigma2 = " + sigma2);

        // Verify signature
        boolean signatureValid = !sigma1.isNeutralElement()
                && e.apply(sigma1, tildeX.op(tildeY.innerProduct(m))).equals(e.apply(sigma2, tildeg));
        if (signatureValid) {
            System.out.println("Signature valid!");
        } else {
            System.out.println("Signature invalid!");
        }
        System.out.println("Done!");
    }

    public static void main(String[] args) {
        doComputations();
    }
}

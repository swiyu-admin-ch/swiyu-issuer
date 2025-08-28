package pmdtest;

public class PMDTest {
    public void test() {
        try {
            int a = 1 / 0;
        } catch (Exception e) {
            // empty catch block triggers PMD violation
        }
    }
}


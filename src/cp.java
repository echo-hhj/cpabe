/**
 * Created with IntelliJ IDEA.
 *
 * @Author: echo-dundun
 * @Date: 2022/04/28/10:16
 * @Description:
 */

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class cp {

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element g_beta = g.powZn(beta).getImmutable();
        Element egg_alpha = bp.pairing(g, g).powZn(alpha).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        mskProp.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));

        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("g_beta", Base64.getEncoder().withoutPadding().encodeToString(g_beta.toBytes()));
        pkProp.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_betaString = pkProp.getProperty("g_beta");
        Element g_beta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_betaString)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String g_alphaString = mskProp.getProperty("g_alpha");
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_alphaString)).getImmutable();
        String betaString = mskProp.getProperty("beta");
        Element beta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(betaString)).getImmutable();

        Properties skProp = new Properties();

        Element r = bp.getZr().newRandomElement().getImmutable();
        Element g_r = g.powZn(r).getImmutable();
        Element one = bp.getZr().newOneElement().getImmutable();
        Element D0 = g_alpha.mul(g_r).getImmutable();
        Element D = D0.powZn(one.div(beta)).getImmutable();

        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));

        for (int att : userAttList) {
            byte[] idHash = sha1(Integer.toString(att));
            Element H = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
            Element r_j = bp.getZr().newRandomElement().getImmutable();
            Element D1 = g_r.mul(H.powZn(r_j)).getImmutable();
            Element D2 = g.powZn(r_j).getImmutable();

            skProp.setProperty("D1-" + att, Base64.getEncoder().withoutPadding().encodeToString(D1.toBytes()));
            skProp.setProperty("D2-" + att, Base64.getEncoder().withoutPadding().encodeToString(D2.toBytes()));
        }

        skProp.setProperty("userAttList", Arrays.toString(userAttList));
        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element message, Node[] accessTree,
                               String pkFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_betaString = pkProp.getProperty("g_beta");
        Element g_beta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_betaString)).getImmutable();
        String egg_alphaString = pkProp.getProperty("egg_alpha");
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(egg_alphaString)).getImmutable();

        Properties ctProp = new Properties();
        //����������� C=M e(g,g)^(alpha s)
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element CT = message.duplicate().mul(egg_alpha.powZn(s)).getImmutable();
        Element C = g_beta.powZn(s).getImmutable();

        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        ctProp.setProperty("CT", Base64.getEncoder().withoutPadding().encodeToString(CT.toBytes()));

        //�����ø��ڵ�Ҫ���������ֵ
        accessTree[0].secretShare = s;
        //���й���ʹ��ÿ��Ҷ�ӽڵ�����Ӧ�����ܷ�Ƭ
        nodeShare(accessTree, accessTree[0], bp);

        for (Node node : accessTree) {
            if (node.isLeaf()) {
                Element r = bp.getZr().newRandomElement().getImmutable();

                byte[] idHash = sha1(Integer.toString(node.att));
                Element Hi = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

                Element C1 = g.powZn(node.secretShare);
                Element C2 = Hi.powZn(node.secretShare);

                ctProp.setProperty("C1-" + node.att, Base64.getEncoder().withoutPadding().encodeToString(C1.toBytes()));
                ctProp.setProperty("C2-" + node.att, Base64.getEncoder().withoutPadding().encodeToString(C2.toBytes()));
            }
        }
        storePropToFile(ctProp, ctFileName);
    }

    public static Element decrypt(String pairingParametersFileName, Node[] accessTree, String ctFileName, String skFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ctProp = loadPropFromFile(ctFileName);

        Properties skProp = loadPropFromFile(skFileName);
        String userAttListString = skProp.getProperty("userAttList");
        //�ָ��û������б� int[]����
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length() - 1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        System.out.println("�û������б�" + userAttListString);

        /*
        Element C0 = message.duplicate().mul(egg_alpha.powZn(s)).getImmutable();
        Element C = g_beta.powZn(s).getImmutable();
         */
        String CString = ctProp.getProperty("C");
        Element C = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CString)).getImmutable();
        String CTString = ctProp.getProperty("CT");
        Element CT = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(CTString)).getImmutable();

        String DString = skProp.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();
//        String D0String = skProp.getProperty("D0");
//        Element D0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D0String)).getImmutable();

        for (Node node : accessTree) {
            if (node.isLeaf()) {
                // ���Ҷ�ӽڵ������ֵ���������б������Զ�Ӧ�������������Կ�����ԵĽ����Ϊ����ֵ
                if (Arrays.stream(userAttList).boxed().collect(Collectors.toList()).contains(node.att)) {
                    String C1tring = ctProp.getProperty("C1-" + node.att);
                    Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1tring)).getImmutable();
                    String C2tring = ctProp.getProperty("C2-" + node.att);
                    Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2tring)).getImmutable();

                    String D1tring = skProp.getProperty("D1-" + node.att);
                    Element D1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D1tring)).getImmutable();
                    String D2tring = skProp.getProperty("D2-" + node.att);
                    Element D2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D2tring)).getImmutable();

                    //String DattString = skProp.getProperty("D"+node.att);
                    //Element Datt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DattString)).getImmutable();

                    node.secretShare = bp.pairing(D1, C1).div(bp.pairing(D2, C2)).getImmutable();
                }
            }
        }
        // �������ָܻ�
        boolean treeOK = nodeRecover(accessTree, accessTree[0], userAttList, bp);
        if (treeOK) {
            Element patialCt = bp.pairing(C, D).div(accessTree[0].secretShare);
            return CT.div(patialCt);
//            Element egg_alphas = bp.pairing(C0,D).div(accessTree[0].secretShare);
//            return C.div(egg_alphas);
        } else {
            System.out.println("The access tree is not satisfied.");
            return null;
        }
    }

    //d-1�ζ���ʽ��ʾΪq(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
    //����ʽ��ϵ������������ΪZr Element���Ӷ��ǵĺ�����ؼ���ȫ����ZrȺ�Ͻ���
    //ͨ�����ѡȡcoef������������d-1�ζ���ʽq(x)��Լ������Ϊq(0)=s��
    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++) {
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    //������coefΪϵ��ȷ���Ķ���ʽqx�ڵ�index����ֵ��ע�����ʽ������ȺZr�Ͻ���
    public static Element qx(Element index, Element[] coef, Pairing bp) {
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++) {
            Element exp = bp.getZr().newElement(i).getImmutable();
            //indexһ��Ҫʹ��duplicate����ʹ�ã���Ϊindex��ÿһ��ѭ���ж�Ҫʹ�ã��������duplicte��index��ֵ�ᷢ���仯
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    //�����������Ӽ��� i�Ǽ���S�е�ĳ��Ԫ�أ�x��Ŀ����ֵ
    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                //ע�⣺��ѭ�����ظ�ʹ�õ���һ��Ҫ��duplicate���Ƴ���ʹ��
                //���xElement��iElement�ظ�ʹ�ã�����Ϊǰ���Ѿ�getImmutable���Կ��Բ���duplicate
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    // ��������
    // nodes�������������нڵ㣬n��Ҫ�������ܵĽڵ�
    public static void nodeShare(Node[] nodes, Node n, Pairing bp) {
        // �����Ҷ�ӽڵ㣬����Ҫ�ٷ���
        if (!n.isLeaf()) {
            // �������Ҷ�ӽڵ㣬��������һ���������ʽ������ʽ�ĳ�����Ϊ��ǰ�ڵ������ֵ�����ֵ�������ڷ���
            // ����ʽ�Ĵ������ɽڵ��gate��Ӧ��threshold����
            Element[] coef = randomP(n.gate[0], n.secretShare, bp);
            for (int j = 0; j < n.children.length; j++) {
                Node childNode = nodes[n.children[j]];
                // ����ÿһ���ӽڵ㣬���ӽڵ������Ϊ�����꣬�����ӽڵ�Ķ���ʽֵ��Ҳ�������Ӧ�����ܷ�Ƭ��
                childNode.secretShare = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                // �ݹ飬�����ӽڵ�����ܼ���������ȥ
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    // �ָ�����
    public static boolean nodeRecover(Node[] nodes, Node n, int[] atts, Pairing bp) {
        if (!n.isLeaf()) {
            // �����ڲ��ڵ㣬ά��һ���ӽڵ������б��������ָܻ���
            List<Integer> validChildrenList = new ArrayList<Integer>();
            int[] validChildren;
            // ����ÿһ���ӽڵ�
            for (int j = 0; j < n.children.length; j++) {
                Node childNode = nodes[n.children[j]];
                // �ݹ���ã��ָ��ӽڵ������ֵ
                if (nodeRecover(nodes, childNode, atts, bp)) {
                    System.out.println("The node with index " + n.children[j] + " is satisfied!");
                    validChildrenList.add(valueOf(n.children[j]));
                    // ��������������ӽڵ�����Ѿ��ﵽ����ֵ��������ѭ�������ټ���ʣ��Ľڵ�
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                } else {
                    System.out.println("The node with index " + n.children[j] + " is not satisfied!");
                }
            }
            // ����ɻָ����ӽڵ������������ֵ���������ӽڵ�����ܷ�Ƭ�ָ���ǰ�ڵ�����ܡ�
            if (validChildrenList.size() == n.gate[0]) {
                validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
                // �����������ղ�ֵ�ָ�����
                // ע�⣬�˴�����ָ�����������������ղ�ֵ
                Element secret = bp.getGT().newOneElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp);  //�����������ղ�ֵ����
                    secret = secret.mul(nodes[i].secretShare.duplicate().powZn(delta)); //���������������ӽ���ָ�����㣬Ȼ������
                }
                n.secretShare = secret;
            }
        } else {
            // �ж�Ҷ�ӽڵ������ֵ�Ƿ����������б�
            // �ж�һ��Ԫ���Ƿ��������飬ע��String���ͺ�int���͵��жϷ�ʽ��ͬ
            if (Arrays.stream(atts).boxed().collect(Collectors.toList()).contains(n.att)) {
                n.valid = true;
            }
        }
        return n.valid;
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-256");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void basicTest() throws Exception {
        int[] userAttList = {1, 2, 3};

//        Node[] accessTree = new Node[7];
//        accessTree[0] = new Node(new int[]{2,3}, new int[]{1,2,3});
//        accessTree[1] = new Node(1);
//        accessTree[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
//        accessTree[3] = new Node(5);
//        accessTree[4] = new Node(2);
//        accessTree[5] = new Node(3);
//        accessTree[6] = new Node(4);

        Node[] accessTree = new Node[5];
        accessTree[0] = new Node(new int[]{3, 4}, new int[]{1, 2, 3, 4});
        accessTree[1] = new Node(1);
        accessTree[2] = new Node(2);
        accessTree[3] = new Node(3);
        accessTree[4] = new Node(4);

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName);
        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName);

        // String msg = "dasddwhqoiuhdaiosnioacjijdqwi0jdaposdjiasojcbndusivbuiweshfsaoindoai";
        // byte[] sha1Result =  sha1(msg);
        Element symmetric = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement();

//        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
//         Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newElement().setFromHash(sha1Result, 0, sha1Result.length).getImmutable();
//         System.out.println("������Ϣ:" + msg);
        File plaintext = new File("File/�ִ�����ѧ.txt");
        int keyLength = 128;
        // �Թ�ϣֵ���нضϻ���䣬ʹ��ﵽָ���ĳ���Ҫ��
        byte[] symmetricBytes = Arrays.copyOf(sha1(String.valueOf(symmetric)), keyLength / Byte.SIZE);

        File encryptionFile = AES.encryptFile(plaintext, symmetricBytes);
        System.out.println("������Ϣ:" + symmetric);
        encrypt(pairingParametersFileName, symmetric, accessTree, pkFileName, ctFileName);

        Element res = decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName);
        System.out.println("���ܽ��:" + res);

        if (symmetric.isEqual(res)) {
            // �Թ�ϣֵ���нضϻ���䣬ʹ��ﵽָ���ĳ���Ҫ��
            byte[] resBytes = Arrays.copyOf(sha1(String.valueOf(res)), keyLength / Byte.SIZE);
            File decryptionFile = AES.decryptFile(encryptionFile, symmetricBytes);
            System.out.println("�ɹ����ܣ�");
        } else {
            System.out.println("����ʧ�ܣ����Բ�����Ҫ�󣡣���");
        }
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }

}


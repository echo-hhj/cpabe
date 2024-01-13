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
        //计算密文组件 C=M e(g,g)^(alpha s)
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element CT = message.duplicate().mul(egg_alpha.powZn(s)).getImmutable();
        Element C = g_beta.powZn(s).getImmutable();

        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        ctProp.setProperty("CT", Base64.getEncoder().withoutPadding().encodeToString(CT.toBytes()));

        //先设置根节点要共享的秘密值
        accessTree[0].secretShare = s;
        //进行共享，使得每个叶子节点获得响应的秘密分片
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
        //恢复用户属性列表 int[]类型
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length() - 1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        System.out.println("用户属性列表：" + userAttListString);

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
                // 如果叶子节点的属性值属于属性列表，则将属性对应的密文组件和秘钥组件配对的结果作为秘密值
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
        // 进行秘密恢复
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

    //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
    //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
    //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=s。
    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++) {
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    //计算由coef为系数确定的多项式qx在点index处的值，注意多项式计算在群Zr上进行
    public static Element qx(Element index, Element[] coef, Pairing bp) {
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++) {
            Element exp = bp.getZr().newElement(i).getImmutable();
            //index一定要使用duplicate复制使用，因为index在每一次循环中都要使用，如果不加duplicte，index的值会发生变化
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    //拉格朗日因子计算 i是集合S中的某个元素，x是目标点的值
    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    // 共享秘密
    // nodes是整颗树的所有节点，n是要分享秘密的节点
    public static void nodeShare(Node[] nodes, Node n, Pairing bp) {
        // 如果是叶子节点，则不需要再分享
        if (!n.isLeaf()) {
            // 如果不是叶子节点，则先生成一个随机多项式，多项式的常数项为当前节点的秘密值（这个值将被用于分享）
            // 多项式的次数，由节点的gate对应的threshold决定
            Element[] coef = randomP(n.gate[0], n.secretShare, bp);
            for (int j = 0; j < n.children.length; j++) {
                Node childNode = nodes[n.children[j]];
                // 对于每一个子节点，以子节点的索引为横坐标，计算子节点的多项式值（也就是其对应的秘密分片）
                childNode.secretShare = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                // 递归，将该子节点的秘密继续共享下去
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    // 恢复秘密
    public static boolean nodeRecover(Node[] nodes, Node n, int[] atts, Pairing bp) {
        if (!n.isLeaf()) {
            // 对于内部节点，维护一个子节点索引列表，用于秘密恢复。
            List<Integer> validChildrenList = new ArrayList<Integer>();
            int[] validChildren;
            // 遍历每一个子节点
            for (int j = 0; j < n.children.length; j++) {
                Node childNode = nodes[n.children[j]];
                // 递归调用，恢复子节点的秘密值
                if (nodeRecover(nodes, childNode, atts, bp)) {
                    System.out.println("The node with index " + n.children[j] + " is satisfied!");
                    validChildrenList.add(valueOf(n.children[j]));
                    // 如果满足条件的子节点个数已经达到门限值，则跳出循环，不再计算剩余的节点
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                } else {
                    System.out.println("The node with index " + n.children[j] + " is not satisfied!");
                }
            }
            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
            if (validChildrenList.size() == n.gate[0]) {
                validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
                // 利用拉格朗日差值恢复秘密
                // 注意，此处是在指数因子上做拉格朗日差值
                Element secret = bp.getGT().newOneElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp);  //计算拉格朗日插值因子
                    secret = secret.mul(nodes[i].secretShare.duplicate().powZn(delta)); //基于拉格朗日因子进行指数运算，然后连乘
                }
                n.secretShare = secret;
            }
        } else {
            // 判断叶子节点的属性值是否属于属性列表
            // 判断一个元素是否属于数组，注意String类型和int类型的判断方式不同
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
//         System.out.println("明文消息:" + msg);
        File plaintext = new File("File/现代密码学.txt");
        int keyLength = 128;
        // 对哈希值进行截断或填充，使其达到指定的长度要求
        byte[] symmetricBytes = Arrays.copyOf(sha1(String.valueOf(symmetric)), keyLength / Byte.SIZE);

        File encryptionFile = AES.encryptFile(plaintext, symmetricBytes);
        System.out.println("明文消息:" + symmetric);
        encrypt(pairingParametersFileName, symmetric, accessTree, pkFileName, ctFileName);

        Element res = decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName);
        System.out.println("解密结果:" + res);

        if (symmetric.isEqual(res)) {
            // 对哈希值进行截断或填充，使其达到指定的长度要求
            byte[] resBytes = Arrays.copyOf(sha1(String.valueOf(res)), keyLength / Byte.SIZE);
            File decryptionFile = AES.decryptFile(encryptionFile, symmetricBytes);
            System.out.println("成功解密！");
        } else {
            System.out.println("解密失败！属性不符合要求！！！");
        }
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }

}


package com.example.quantile;

import java.io.*;

public class Main {

    public static void main(String[] args) {
        splitZip("test.zip", "lol");
    }

    public static synchronized int splitZip(String fileSrc, String destSrc) {
        File file = new File(fileSrc);
        if (!file.exists()) {
            System.out.println("File does not exist!");
            return 0;
        }
        long countFileSize = file.length();
//        long oneFileSize = 1024 * 1024 * 200;
        long oneFileSize = 1024 * 50;
        int partNum = 0;
        if (countFileSize % oneFileSize == 0) {
            partNum = (int) (countFileSize / oneFileSize);
        } else {
            partNum = (int) (countFileSize / oneFileSize) + 1;
        }
        System.out.println("Number of split files: " + partNum);

        InputStream in;
        try {
            in = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(in);
            BufferedOutputStream bos = null;

            byte bytes[] = new byte[1024];

            for (int i = 0; i < partNum; i++) {
                String newFileSrc = destSrc + "part-" + i + ".zip";
                File newFile = new File(newFileSrc);
//                if (!newFile.getParentFile().exists()) {
//                    System.out.println("Create file split directory!");
//                    newFile.getParentFile().mkdirs();
//                }

                bos = new BufferedOutputStream(new FileOutputStream(newFile));
                int readSize = -1;
                int count = 0;
                while ((readSize = bis.read(bytes)) != -1) {
                    bos.write(bytes, 0, readSize);
                    bos.flush();
                    count += readSize;
                    if (count >= oneFileSize) {
                        break;
                    }
                }
            }
            bis.close();
            in.close();
            bos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return partNum;
    }

}

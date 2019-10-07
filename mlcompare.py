from sklearn.linear_model import LogisticRegression
from sklearn.linear_model import Perceptron
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
import numpy as np
from sklearn.cross_validation import train_test_split
import pandas as pd

def test_on_one_detect(classifier):
    S0 = np.array([[0,0,0,0,0]])
    S1 = np.array([[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]])
    S2 = np.array([[0,0,0,1,1],[0,0,1,0,1], [0,0,1,1,0], [0,1,0,0,1], [0,1,0,1,0], [0,1,1,0,0],
                   [1,0,0,0,1], [1,0,0,1,0], [1,0,1,0,0], [1,1,0,0,0]])
    S4 = np.array([[1,1,1,1,0],[1,1,1,0,1],[1,1,0,1,1],[1,0,1,1,1],[0,1,1,1,1]])
    S5 = np.array([[1,1,1,1,1]])
    print classifier.predict(S0), classifier.predict(S1), classifier.predict(S2), classifier.predict(S4), classifier.predict(S5)

def report(classifier_name, y_test, y_pred):
    acc = 100 * np.round(accuracy_score(y_test, y_pred), 3)
    cm = confusion_matrix(y_test, y_pred)
    tn = cm[0][0]
    fn = cm[1][0]
    tp = cm[1][1]
    fp = cm[0][1]
    print '{}, Test collection size {:5},  Acc. {}%, TP {:5}, FP {}, TN {:5}, FN {:5}'.format(classifier_name, len(y_test), acc, tp, fp, tn, fn)

def testvirussign(testdata, classifier, clname):
    df2 = pd.read_csv(testdata, delimiter=',')
    df2.fillna(0)
    X2 = df2[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y2 = df2['Malware']
    y2_pred = classifier.predict(X2)
    report(clname, y2, y2_pred)

def try_perceptron(datapath, testpath):
    df = pd.read_csv(datapath, delimiter=',')
    df.fillna(0)
    X = df[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y = df['Malware']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    ppn = Perceptron(n_iter=400, eta0=0.1, random_state=0)
    ppn.fit(X_train, y_train)
    y_pred = ppn.predict(X_test)
    classifier_name = 'perceptron          '
    report(classifier_name, y_test, y_pred)
    testvirussign(testpath, ppn, classifier_name)

def try_logistic_regression(datapath, testpath):
    df = pd.read_csv(datapath, delimiter=',')
    df.fillna(0)
    X = df[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y = df['Malware']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    lr = LogisticRegression(C = 1000.0, random_state=0)
    lr.fit(X_train, y_train)
    y_pred = lr.predict(X_test)
    classifier_name = 'logistic regression '
    report(classifier_name, y_test, y_pred)
    testvirussign(testpath, lr, classifier_name)
    # test_on_one_detect(lr)
    # print lr.coef_, lr.intercept_

def try_svm(datapath, testpath):
    df = pd.read_csv(datapath, delimiter=',')
    df.fillna(0)
    X = df[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y = df['Malware']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    svm = SVC (kernel='rbf', C=1.0, random_state=0)
    svm.fit(X_train, y_train)
    y_pred = svm.predict(X_test)
    classifier_name = 'svm                 '
    report(classifier_name, y_test, y_pred)
    testvirussign(testpath, svm, classifier_name)
    # test_on_one_detect(svm)

def try_decision_tree(datapath, testpath):
    df = pd.read_csv(datapath, delimiter=',')
    df.fillna(0)
    X = df[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y = df['Malware']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    tree = DecisionTreeClassifier(criterion='entropy', max_depth=4, random_state=0)
    tree.fit(X_train, y_train)
    y_pred = tree.predict(X_test)
    classifier_name = 'decision tree       '
    report(classifier_name, y_test, y_pred)
    testvirussign(testpath, tree, classifier_name)
    # test_on_one_detect(tree)

def try_random_forest(datapath, testpath):
    df = pd.read_csv(datapath, delimiter=',')
    df.fillna(0)
    X = df[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y = df['Malware']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    forest = RandomForestClassifier(criterion='entropy',
                                    n_estimators=10,
                                    random_state=1,
                                    n_jobs=2)
    forest.fit(X_train, y_train)
    y_pred = forest.predict(X_test)
    classifier_name = 'random forest       '
    report(classifier_name, y_test, y_pred)
    testvirussign(testpath, forest, classifier_name)
    # test_on_one_detect(forest)

def try_knn(datapath, testpath):
    df = pd.read_csv(datapath, delimiter=',')
    df.fillna(0)
    X = df[['Avira', 'ClamAV', 'DrWeb', 'ESET-NOD32', 'Kaspersky']]
    y = df['Malware']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)
    knn = KNeighborsClassifier(n_neighbors=5, p=2, metric='minkowski')
    knn.fit(X_train, y_train)
    y_pred = knn.predict(X_test)
    classifier_name = 'knn                 '
    report(classifier_name, y_test, y_pred)
    testvirussign(testpath, knn, classifier_name)
    # test_on_one_detect(knn)

def main():

    testpath = "testing\\exe\\data.csv"
    datapath = "training\\exe\\data.csv"

    try_perceptron(datapath, testpath)
    try_logistic_regression(datapath, testpath)
    try_svm(datapath, testpath)
    try_decision_tree(datapath, testpath)
    try_random_forest(datapath, testpath)
    try_knn(datapath, testpath)

    # Manual evaluating antiviruses
    # df = pd.read_csv(datapath, delimiter=',')
    # print df.corr()

    # Manual test on SWF collection
    # W = np.array([4.62258512, 0.53464145, 0.58425391, 11.30633915, 11.85448717])
    # C = -6.44589667
    # print '[0] [0 0 0 1 1] [1 1 1 1 1 0 1 1 0 0] [1 1 1 1 1] [1]'

    # Manual test on EXE collection
    # W = np.array([ 11.85487083,   3.94320718,  -0.81163648,  12.9871951,   -1.47310427])
    # C = -6.67365596
    # print '[0] [1 0 0 1 0] [1 0 1 0 1 0 1 1 1 1] [1 1 1 1 1] [1]'

    # S0 = np.array([[0,0,0,0,0]])
    # S1 = np.array([[1,0,0,0,0],[0,1,0,0,0],[0,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]])
    # S2 = np.array([[0,0,0,1,1],[0,0,1,0,1], [0,0,1,1,0], [0,1,0,0,1], [0,1,0,1,0], [0,1,1,0,0],
    #                [1,0,0,0,1], [1,0,0,1,0], [1,0,1,0,0], [1,1,0,0,0]])
    # S4 = np.array([[1,1,1,1,0],[1,1,1,0,1],[1,1,0,1,1],[1,0,1,1,1],[0,1,1,1,1]])
    # S5 = np.array([[1,1,1,1,1]])
    #
    #
    # print (np.sign(np.dot(S0, W) + C).astype(int) + 1 ) / 2, (np.sign(np.dot(S1, W) + C).astype(int) + 1 ) / 2, \
    #     (np.sign(np.dot(S2, W) + C).astype(int) + 1 ) / 2, (np.sign(np.dot(S4, W) + C).astype(int) + 1 ) / 2,\
    #     (np.sign(np.dot(S5, W) + C).astype(int) + 1 ) / 2



if __name__ == "__main__":
    main()
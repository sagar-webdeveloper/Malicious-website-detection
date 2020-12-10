
import pandas as pd

import numpy as np

import matplotlib.pyplot as plt

import seaborn as sns

# Commented out IPython magic to ensure Python compatibility.
# %matplotlib inline


df = pd.read_csv('dataset//KNN-Dataset-heading.csv')


df.head()

from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()

scaler.fit(df.drop('result',axis=1))

scaled_features = scaler.transform(df.drop('result',axis=1))

scaled_features

df_feat=pd.DataFrame(scaled_features,columns=df.columns[:-1])

df_feat.head

from sklearn.model_selection import train_test_split

X=df_feat
y=df['result']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=101)

from sklearn.neighbors import KNeighborsClassifier

knn = KNeighborsClassifier(n_neighbors=9)

knn.fit(X_train,y_train)

pred = knn.predict(X_test)

from sklearn.metrics import classification_report,confusion_matrix

print(confusion_matrix(y_test,pred))
print(classification_report(y_test,pred))

error_rate = []

for i in range(1,50):

    knn = KNeighborsClassifier(n_neighbors=i)
    knn.fit(X_train,y_train)
    pred_i = knn.predict(X_test)
    error_rate.append(np.mean(pred_i != y_test))

plt.figure(figsize=(10,6))
plt.plot(range(1,50),error_rate,color='blue',linestyle='--',marker='o',markerfacecolor='red',markersize=10)
plt.title('error rate vs k')


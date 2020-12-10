# first neural network with keras tutorial
from numpy import loadtxt
from keras.models import Sequential
from keras.layers import Dense
from keras.layers import Dropout
# load the dataset
dataset = loadtxt('Dataset//KNN-Dataset.csv', delimiter=',')
# split into input (X) and output (y) variables
X = dataset[:,0:16]
y = dataset[:,16]
# define the keras model
model = Sequential()
model.add(Dense(3, input_dim=16, activation='relu'))
model.add(Dense(4, activation='relu'))
model.add(Dense(1, activation='sigmoid'))
model.add(Dropout(0.01))
# compile the keras model
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
# fit the keras model on the dataset
model.fit(X, y, epochs=150, batch_size=20)
# evaluate the keras model
_, accuracy = model.evaluate(X, y)
print('Accuracy: %.2f' % (accuracy*100))
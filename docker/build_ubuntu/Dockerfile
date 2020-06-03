FROM ubuntu:18.04
RUN apt-get update && apt-get install build-essential wget unzip openssl libssl-dev -y

RUN wget https://github.com/Kitware/CMake/releases/download/v3.17.3/cmake-3.17.3-Linux-x86_64.sh
RUN chmod +x cmake-3.17.3-Linux-x86_64.sh
RUN ./cmake-3.17.3-Linux-x86_64.sh --skip-license
RUN wget https://dl.bintray.com/boostorg/release/1.72.0/source/boost_1_72_0.tar.gz
RUN tar -xf boost_1_72_0.tar.gz
RUN cp -r boost_1_72_0/boost /usr/local/include
RUN wget https://cryptopp.com/cryptopp820.zip
RUN unzip cryptopp820.zip 
RUN make
RUN make install 

RUN mkdir /home/threePP
WORKDIR /home/threePP

ADD ./src ./src
ADD ./cert ./cert
COPY ./CMakeLists.txt ./

RUN cmake . &&  make dockerInstance -j 6 && make dockerAuthority -j 6

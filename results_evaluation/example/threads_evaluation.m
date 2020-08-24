threads = readtable('./threads.csv', 'Format', '%C%f%f%f%f%f%f%f%f%f')

threads = sortrows(threads, 3);

cmap = [0.00,0.45,0.74; 0.85,0.33,0.10; 0.93,0.69,0.13]
[group, id] = findgroups(threads.nodes);

absolutefunc = @(nodes, medi) [nodes(1), medi'];
absoluteresult = splitapply(absolutefunc, threads.nodes, threads.medi, group);
aggregate = [[1*ones(9,1) absoluteresult(:,1) absoluteresult(:,2)]; [2*ones(9,1) absoluteresult(:,1) absoluteresult(:,3)]; [4*ones(9,1) absoluteresult(:,1) absoluteresult(:,4)]]

speedupfunc = @(n,t1,t2,t4) [n, 1, t1/t2, t1/t4];
speedupresult = table2array(rowfun(speedupfunc, array2table(absoluteresult)))
suag = [[1*ones(9,1) speedupresult(:,1) speedupresult(:,2)]; [2*ones(9,1) speedupresult(:,1) speedupresult(:,3)]; [4*ones(9,1) speedupresult(:,1) speedupresult(:,4)]]

fig = figure;

subplot(1,2,1)
gg = gscatter(aggregate(:,2), aggregate(:,3), aggregate(:,1), cmap, '', 20)
gg(1).DisplayName = "1 Thread"
gg(2).DisplayName = "2 Threads"
gg(3).DisplayName = "4 Threads"
colormap(cmap)
ylabel("Median runtime [s]")
xlabel("Absolute runtime")
xlim([7,25])
xticks([8,10,12,14,16,18,20,22,24])

subplot(1,2,2)
gscatter(suag(:,2), suag(:,3), suag(:,1), cmap, '', 20)
h = legend()
set(h,"visible","off")
ylabel("Speedup (1 Thread/x Threads)")
xlabel("Speedup")
ylim([0.9,2.2])
xlim([7,25])
xticks([8,10,12,14,16,18,20,22,24])

han = axes(fig,'visible', 'off');
han.XLabel.Visible='on';
xlabel(han, "# Participants")
nodes = readtable('./nodes.csv', 'Format', '%C%d%d%d%f%f%f%f%f%f')

U = nodes(nodes.category == 'u',:);
S = nodes(nodes.category == 's',:);
fig = figure;

subplot(1,2,1)
errorbar(U{:,2},U{:,7},U{:,7}-U{:,5},U{:,7}-U{:,10}, 'LineStyle', 'none', 'Marker', 'x')

set(gca,'yscale','log')
ylim([0.1,50])

xlabel("Unsecured")
xlim([7,25])
xticks([8,10,12,14,16,18,20,22,24])

subplot(1,2,2)
errorbar(S{:,2},S{:,7},S{:,7}-S{:,5},S{:,7}-S{:,10}, 'LineStyle', 'none', 'Marker', 'x')

set(gca,'yscale','log')
ylim([0.1,50])

xlabel("Secured")
xlim([7,25])
xticks([8,10,12,14,16,18,20,22,24])

han = axes(fig,'visible', 'off');

han.XLabel.Visible='on';
xlabel(han, "# Participants")

han.YLabel.Visible='on';
ylabel(han, "Time [s]")

% han.Title.Visible='on';
% title(han,"Min, Median, Max Runtime by # Participants")